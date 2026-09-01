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

var globalTP *sdktrace.TracerProvider

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
	defer srcTP.Shutdown(ctx)
	defer dstTP.Shutdown(ctx)
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

//func NetworkTraceLog[T utils.NetworkEvent](octoEvent utils.Output[T]) {
//	event := utils.NetworkEvent(octoEvent.Data)
//	ctx := context.Background()
//
//	tempoHost := os.Getenv("TEMPO_HOST")
//	if tempoHost == "" {
//		tempoHost = "tempo.monitoring.svc.cluster.local:4318"
//	}
//
//	exporter, err := otlptracehttp.New(ctx,
//		otlptracehttp.WithEndpoint(tempoHost),
//		otlptracehttp.WithInsecure(),
//	)
//	if err != nil {
//		return
//	}
//
//	res, err := resource.New(ctx,
//		resource.WithAttributes(
//			semconv.ServiceNameKey.String(event.Source), // SOURCE node
//		),
//	)
//	if err != nil {
//		return
//	}
//
//	tp := sdktrace.NewTracerProvider(
//		sdktrace.WithSyncer(exporter),
//		sdktrace.WithResource(res),
//	)
//	defer tp.Shutdown(ctx)
//
//	tracer := tp.Tracer("octagon-force-network")
//	_, span := tracer.Start(ctx, event.EventType,
//		trace.WithSpanKind(trace.SpanKindClient),
//	)
//	span.SetAttributes(
//		attribute.String("peer.service", event.Destination), // DESTINATION node
//	)
//	span.End()
//}
//
////func sendOTLPTrace(ctx context.Context) error {
////	if globalTP == nil {
////		tempoHost := os.Getenv("TEMPO_HOST")
////		if tempoHost == "" {
////			tempoHost = "tempo.monitoring.svc.cluster.local:4318"
////		}
////
////		exporter, err := otlptracehttp.New(ctx,
////			otlptracehttp.WithEndpoint(tempoHost),
////			otlptracehttp.WithInsecure(),
////		)
////		if err != nil {
////			return fmt.Errorf("exporter error: %w", err)
////		}
////
////		// Defines the SOURCE node name on the Service Graph
////		res, err := resource.New(ctx,
////			resource.WithAttributes(
////				semconv.ServiceNameKey.String("octagon-force-network"),
////			),
////		)
////		if err != nil {
////			return fmt.Errorf("resource error: %w", err)
////		}
////
////		// Uses Syncer for immediate HTTP dispatch per event
////		globalTP = sdktrace.NewTracerProvider(
////			sdktrace.WithSyncer(exporter),
////			sdktrace.WithResource(res),
////		)
////
////		otel.SetTracerProvider(globalTP)
////	}
////
////	return globalTP.ForceFlush(ctx)
////}
////
////// 2. Event Handler: Sets Span Kind and Peer Service for Graph Edges
////func NetworkTraceLog[T utils.NetworkEvent](octoEvent utils.Output[T]) {
////	event := utils.NetworkEvent(octoEvent.Data)
////	ctx := context.Background()
////
////	if err := sendOTLPTrace(ctx); err != nil {
////		// Log warning or handle error
////	}
////
////	tracer := otel.Tracer("octagon-force-network")
////
////	// SpanKindClient tells Tempo this span represents outbound client traffic
////	ctx, span := tracer.Start(ctx, event.EventType,
////		trace.WithSpanKind(trace.SpanKindClient),
////	)
////
////	// Set standard attributes for Service Graph edge resolution
////	span.SetAttributes(
////		// 'peer.service' tells Tempo what the DESTINATION node name is
////		attribute.String("peer.service", event.Destination),
////		attribute.String("server.address", event.Destination),
////		attribute.String("client.address", event.Source),
////		attribute.String("source", event.Source),
////		attribute.String("destination", event.Destination),
////	)
////
////	// Attach as an in-trace timestamped event
////	span.AddEvent("network_event_captured", trace.WithAttributes(
////		attribute.String("source", event.Source),
////		attribute.String("destination", event.Destination),
////		attribute.String("event.type", event.EventType),
////	))
////
////	// Close span after attributes are set so complete data is sent
////	span.End()
////}
////
//////func sendOTLPTrace(ctx context.Context) error {
//////	if globalTP == nil {
//////		tempoHost := os.Getenv("TEMPO_HOST")
//////		if tempoHost == "" {
//////			tempoHost = "tempo.monitoring.svc.cluster.local:4318"
//////		}
//////
//////		exporter, err := otlptracehttp.New(ctx,
//////			otlptracehttp.WithEndpoint(tempoHost), // host:port without http://
//////			otlptracehttp.WithInsecure(),
//////		)
//////		if err != nil {
//////			return fmt.Errorf("exporter error: %w", err)
//////		}
//////
//////		// Use Syncer instead of Batcher if you want immediate synchronous HTTP delivery per event
//////		globalTP = sdktrace.NewTracerProvider(
//////			sdktrace.WithSyncer(exporter),
//////		)
//////
//////		// Register it so otel.Tracer() routes spans to this provider
//////		otel.SetTracerProvider(globalTP)
//////	}
//////
//////	// Flush the provider that actually owns the spans
//////	return globalTP.ForceFlush(ctx)
//////}
//////
//////func NetworkTraceLog[T utils.NetworkEvent](octoEvent utils.Output[T]) {
//////	event := utils.NetworkEvent(octoEvent.Data)
//////	ctx := context.Background()
//////
//////	// Ensure the provider and exporter are wired up first
//////	if err := sendOTLPTrace(ctx); err != nil {
//////		log.Warn(err.Error())
//////	}
//////
//////	// Now otel.Tracer() targets globalTP
//////	tracer := otel.Tracer("octagon-force-network")
//////	_, span := tracer.Start(ctx, event.EventType)
//////
//////	span.SetAttributes(
//////		attribute.String("source", event.Source),
//////		attribute.String("destination", event.Destination),
//////	)
//////
//////	span.AddEvent("network_event_captured", trace.WithAttributes(
//////		attribute.String("source", event.Source),
//////		attribute.String("destination", event.Destination),
//////		attribute.String("event.type", event.EventType),
//////	))
//////
//////	// Close span after attributes/events are set so the syncer transmits complete data
//////	span.End()
//////}
//////
//////
