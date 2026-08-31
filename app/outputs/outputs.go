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
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
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

func sendOTLPTrace(ctx context.Context) error {
	tempoHost := os.Getenv("TEMPO_HOST")
	if tempoHost == "" {
		tempoHost = "tempo.monitoring.svc.cluster.local:4318"
	}

	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(tempoHost), // host:port without http://
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return fmt.Errorf("exporter error: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
	)

	// Force immediate flush of the current trace span
	return tp.ForceFlush(ctx)
}

// Your actual event handler (clean and minimal)
func NetworkTraceLog[T utils.NetworkEvent](octoEvent utils.Output[T]) {
	event := utils.NetworkEvent(octoEvent.Data)
	ctx := context.Background()

	tracer := otel.Tracer("octagon-force-network")
	_, span := tracer.Start(context.Background(), event.EventType)
	defer span.End()

	span.SetAttributes(
		attribute.String("source", event.Source),
		attribute.String("destination", event.Destination),
	)

	// 2. Attach Span Event
	span.AddEvent("network_event_captured", trace.WithAttributes(
		attribute.String("source", event.Source),
		attribute.String("destination", event.Destination),
		attribute.String("event.type", event.EventType),
	))

	// 3. Delegate sending logic to the lower-level helper
	_ = sendOTLPTrace(ctx)

}

//func LogWithTrace(ctx context.Context, logger slog.Logger, level slog.Level, msg string, attrs ...slog.Attr) {
//	span := trace.SpanFromContext(ctx)
//	if span.SpanContext().IsValid() {
//		attrs = append(attrs, slog.String("trace_id", span.SpanContext().TraceID().String()))
//		attrs = append(attrs, slog.String("span_id", span.SpanContext().SpanID().String()))
//	}
//	logger.LogAttrs(ctx, level, msg, attrs...)
//}
//
//func NetworkTraceLog[T utils.NetworkEvent](octoEvent utils.Output[T]) {
//	convertedEvent := utils.NetworkEvent(octoEvent.Data)
//	baseHandler := slog.New(slog.NewJSONHandler(os.Stdout, nil))
//	traceer := otel.Tracer("octagon-force-network")
//
//	ctx, span := traceer.Start(context.Background(), "NetworkEvent")
//	defer span.End()
//
//	LogWithTrace(ctx, *baseHandler, slog.LevelInfo, convertedEvent.EventType, slog.String(convertedEvent.Destination, convertedEvent.Source))
//}
//
//func Enqueue[T utils.EventData](queue []utils.Output[T], element utils.Output[T]) []utils.Output[T] {
//	queue = append(queue, element) // Simply append to enqueue.
//	fmt.Println("Enqueued:", element)
//	return queue
//}
//
//func Dequeue[T utils.EventData](queue []utils.Output[T]) []utils.Output[T] {
//	element := queue[0] // The first element is the one to be dequeued.
//	fmt.Println("Dequeued:", element)
//	return queue[1:] // Slice off the element once it is dequeued.
//}
