package outputs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/Ceald1/octagon-force/app/outputs/utils"
	"github.com/charmbracelet/log"
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
