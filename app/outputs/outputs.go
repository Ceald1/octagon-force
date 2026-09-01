package outputs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Ceald1/octagon-force/app/outputs/utils"
	"github.com/charmbracelet/log"
	// "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

const LokiOut string = "Loki"

const LokiContentType = "application/json"

func NewLokiPayload[T utils.EventData](octagonData utils.Output[T]) error {

	switch any(octagonData.Data).(type) {
	case utils.NetworkEvent:
		octagonData.EventName = "network"
	case utils.SigmaEvent:
		octagonData.EventName = "sigma"

	case utils.FileSystemEvent:
		octagonData.EventName = "file_system"

	}
	jsBytes, err := json.Marshal(octagonData)
	if err != nil {
		log.Error("failed to marshal octagon data", "err", err)
		return err
	}

	// Loki expects nanoseconds formatted as a string representation of an integer
	timestampStr := strconv.FormatInt(time.Now().UnixNano(), 10)
	result := map[string]any{
		"streams": []map[string]any{
			{
				"stream": map[string]string{
					"job": "octagon-force",
				},
				"values": [][]string{
					{timestampStr, string(jsBytes)},
				},
			},
		},
	}

	lokiHost := os.Getenv("LOKI_HOST")
	if lokiHost == "" {
		lokiHost = "loki-headless.monitoring.svc.cluster.local"
	}

	body, err := json.Marshal(result)
	if err != nil {
		log.Error("failed to marshal loki payload", "err", err)
		return err
	}

	resp, err := http.Post(
		fmt.Sprintf("http://%s/loki/api/v1/push", lokiHost),
		LokiContentType,
		bytes.NewBuffer(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("loki error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func NetworkTraceLog[T utils.NetworkEvent](octoEvent utils.Output[T]) {
	event := utils.NetworkEvent(octoEvent.Data)
	ctx := context.Background()
	tempoHost := os.Getenv("TEMPO_HOST")
	if tempoHost == "" {
		tempoHost = "tempo.monitoring.svc.cluster.local:4318"
	}
	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(tempoHost),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return
	}
	// Two resources, one per IP, so src and dest end up as different
	// service.name values on their respective spans.
	resoledName, ns, err := utils.ResolveIP(event.Source)
	if err != nil {
		resoledName = event.Source
		log.Warn(err.Error())
	} else {
		resoledName = fmt.Sprintf("%s.%s", resoledName, ns)
	}
	srcRes, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceNameKey.String(resoledName)),
	)
	if err != nil {
		log.Warn(err.Error())
		return
	}
	resoledNameD, nsD, err := utils.ResolveIP(event.Destination)
	if err != nil {
		log.Warn(err.Error())
		resoledNameD = event.Destination
	} else {
		resoledNameD = fmt.Sprintf("%s.%s", resoledNameD, nsD)
	}
	dstRes, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceNameKey.String(resoledNameD)),
	)
	if err != nil {
		log.Warn(err.Error())
		return
	}
	srcTP := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(srcRes),
	)
	dstTP := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(dstRes),
	)
	defer func() {
		_ = srcTP.ForceFlush(ctx)
		_ = dstTP.ForceFlush(ctx)
		_ = srcTP.Shutdown(ctx)
		_ = dstTP.Shutdown(ctx)
	}()
	// Client span: source IP making the call.
	clientCtx, clientSpan := srcTP.Tracer("octagon-force-network").Start(ctx, event.EventType,
		trace.WithSpanKind(trace.SpanKindClient),
	)
	clientSpan.SetAttributes(
		attribute.String("peer.service", resoledNameD),
	)
	clientSpan.End()
	// Server span: child of the client span (same trace, parent_span_id
	// set), but attributed to the destination IP. This src->dest parent-child
	// link across two different service.name values is what SigNoz's
	// dependency graph needs to draw an edge.
	_, serverSpan := dstTP.Tracer("octagon-force-network").Start(clientCtx, event.EventType,
		trace.WithSpanKind(trace.SpanKindServer),
	)
	serverSpan.End()
}
