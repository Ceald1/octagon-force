package sigma

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"os"

	"time"

	"context"

	"gopkg.in/yaml.v3"

	"github.com/Ceald1/octagon-force/app/outputs"
	"github.com/Ceald1/octagon-force/app/outputs/utils"
	s "github.com/bradleyjkemp/sigma-go"
	se "github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/charmbracelet/log"
	"github.com/cilium/ebpf"
)

func cString(b []byte) string {
	// Find the null terminator
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		// No null terminator found, use entire array
		n = len(b)
	}
	return string(b[:n])
}

var ctx context.Context = context.Background()

type proc_key struct {
	Pid        uint32
	_          uint32 // IMPORTANT padding
	Start_time uint64
}

type Sigma_event struct {
	SourcePID   uint32
	_           uint32
	ContainerID uint64
	Data        [256]byte

	Hooked [16]byte
}

type Log struct {
	Name string `json:"name"`

	Level       string `json:"action"`
	Message     string `json:"message"`
	ContainerID uint64 `json:"containerID"`
}

func GetRules() (rules []s.Rule, err error) {
	data, err := os.ReadFile("./rules/sigma.yaml")
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var docBytes []byte
	var rule s.Rule

	for {
		var doc yaml.Node
		err = dec.Decode(&doc)
		if err == io.EOF {
			err = nil
			break
		}
		docBytes, err = yaml.Marshal(&doc)
		if err != nil {
			return
		}

		rule, err = s.ParseRule(docBytes)
		if err != nil {
			return
		}
		rules = append(rules, rule)
	}

	return
}

func ParseRules(rules []s.Rule, Sevent Sigma_event) (err error) {

	evaluator := se.ForRules(rules)
	var e map[string]string
	hooked := cString(Sevent.Hooked[:])
	switch hooked {
	case "sys_enter_write":
		e = map[string]string{
			"Image": "sys_enter_write",
			"Data":  base64.RawStdEncoding.EncodeToString(Sevent.Data[:]),
		}
	case "check_security":
		e = map[string]string{
			"Image": "check_security",
			"Data":  cString(Sevent.Data[:]),
		}
	case "network":
		e = map[string]string{
			"Image": "network",
			"Data":  base64.RawStdEncoding.EncodeToString(Sevent.Data[:]),
		}
	default:
		return
	}
	results, err := evaluator.Matches(ctx, e)
	if err != nil {
		log.Warn("evaluator error", "err", err)
	}

	for _, result := range results {

		if result.Match {
			output := utils.SigmaEvent{
				Name:         result.Title,
				Level:        result.Level,
				Message:      result.Description,
				ContainerID:  fmt.Sprintf("%d", Sevent.ContainerID),
				ContainerPID: fmt.Sprintf("%d", Sevent.SourcePID),
			}
			outLog := utils.Output[utils.SigmaEvent]{
				Data: output,
			}
			podName, ns, err := outLog.GetPod()
			if err != nil {
				log.Warn(fmt.Sprintf("cannot get pod name for: %d", Sevent.SourcePID))
			}
			outLog.Source = podName
			outLog.Data.Namespace = ns
			err = outputs.NewLokiPayload(outLog)
			if err != nil {
				log.Warn(err.Error())
			}
		}
	}

	return
}

const exec_sigma = "/sys/fs/bpf/octagon_force/sigma_exec/octagon_force_sigma_event_map_pin"
const write_sigma = "/sys/fs/bpf/octagon_force/sigma_write/octagon_force_sigma_event_map_pin"
const fork_sigma = "/sys/fs/bpf/octagon_force/sigma_proc/octagon_force_sigma_event_map_pin"

func Exec_Run(rules []s.Rule) {
	prog, err := ebpf.LoadPinnedMap(exec_sigma, nil)
	if err != nil {
		log.Warn("could not load sigma_exec.")
		return
	}
	defer prog.Close()
	for {
		var Sevent Sigma_event
		it := prog.Iterate()
		var key proc_key
		for it.Next(&key, &Sevent) {
			err := prog.Delete(&key)
			if err != nil {
				log.Warn("delete failed:", err)
			}
			go func() {
				err = ParseRules(rules, Sevent)
				if err != nil {
					log.Warn(err)
				}
			}()
		}
		time.Sleep(100 * time.Millisecond)

	}
}

func Write_Run(rules []s.Rule) {
	prog, err := ebpf.LoadPinnedMap(write_sigma, nil)
	if err != nil {
		log.Warn("could not load sigma_write.")
		return
	}
	defer prog.Close()
	for {
		var Sevent Sigma_event
		it := prog.Iterate()
		var key proc_key
		for it.Next(&key, &Sevent) {
			err := prog.Delete(&key)
			if err != nil {
				log.Warn("delete failed:", err)
			}
			go func() {
				err = ParseRules(rules, Sevent)
				if err != nil {
					log.Warn(err)
				}
			}()
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func Fork_Run(rules []s.Rule) {
	prog, err := ebpf.LoadPinnedMap(fork_sigma, nil)
	if err != nil {
		log.Warn("could not load sigma_write.")
		return
	}
	defer prog.Close()
	for {
		var Sevent Sigma_event
		it := prog.Iterate()
		var key proc_key
		for it.Next(&key, &Sevent) {
			err := prog.Delete(&key)
			if err != nil {
				log.Warn("delete failed:", err)
			}
			go func() {
				err = ParseRules(rules, Sevent)
				if err != nil {
					log.Warn(err)
				}
			}()
		}
		time.Sleep(100 * time.Millisecond)
	}
}
