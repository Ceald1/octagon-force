package file_system_monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/flosch/pongo2/v7"

	"github.com/cilium/ebpf"
	"gopkg.in/yaml.v3"
)

type Octagon_Force_FileSystemEnforcerMap struct {
	FileAccessed [32]byte // 0
	SourcePID    uint32   // 32
	_            uint32   // 36
	ContainerID  uint64   // 40
	Action       bool     // 48
	RuleName     [32]byte // 49 — no padding, char has align 1
	_            [7]byte  // 81 — tail padding to reach 88
}

type Octagon_Force_FileSystemEnforcerRule struct {
	Name     [32]byte
	FileName [32]byte
	Action   bool
}

type Rule struct {
	Name     string `yaml:"name"`
	FileName string `yaml:"filename"`
	Action   string `yaml:"action"`
	Message  string `yaml:"message"`
}

type proc_key struct {
	Pid        uint32
	_          uint32 // IMPORTANT padding
	Start_time uint64
}

type Log struct {
	Name        string `json:"name"`
	FileName    string `json:"filename"`
	Action      string `json:"action"`
	Message     string `json:"message"`
	ContainerID uint64 `json:"containerID"`
}

type RuleFile struct {
	Rules []Rule `yaml:"rules"` // array of rule files
}

var RULEMAP map[string]Rule = make(map[string]Rule)

func UpdateRules(rules []Rule) {
	prog, err := ebpf.LoadPinnedMap("/sys/fs/bpf/octagon_force/filesystem_monitor/octagon_force_filesystem_monitor_enforcer_rules_pin", nil)
	if err != nil {
		log.Warn("failed to update filesystem_monitor rules.")
		return
	}
	defer prog.Close()

	for i := 0; i < 100; i++ {
		var newRule Octagon_Force_FileSystemEnforcerRule

		if i < len(rules) {
			rule := rules[i]
			RULEMAP[rule.Name] = rule
			copy(newRule.FileName[:], rule.FileName)
			copy(newRule.Name[:], rule.Name)
			if strings.ToLower(rule.Action) == "deny" {
				newRule.Action = false
			} else {
				newRule.Action = true
			}
		}
		// if i >= len(rules), newRule is zero value — clears the slot

		err = prog.Update(uint32(i), newRule, ebpf.UpdateAny)
		if err != nil {
			panic(err)
		}
	}
}

func ParseRules() (rules []Rule) {
	data, err := os.ReadFile("./rules/file_system_monitor.yaml")
	if err != nil {
		panic(err)
	}
	var ruleFile RuleFile

	err = yaml.Unmarshal(data, &ruleFile)
	if err != nil {
		panic(err)
	}
	// check templates too
	for _, rule := range ruleFile.Rules {
		_, err = pongo2.FromString(rule.Message)
		if err != nil {
			panic(err)
		}
	}
	rules = ruleFile.Rules

	return
}
func cString(b []byte) string {
	// Find the null terminator
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		// No null terminator found, use entire array
		n = len(b)
	}
	return string(b[:n])
}

func Run() {
	prog, err := ebpf.LoadPinnedMap("/sys/fs/bpf/octagon_force/filesystem_monitor/octagon_force_filesystem_monitor_enforcer_map_pin", nil)
	if err != nil {
		log.Warn("could not load filesystem_monitor.")
		return
	}
	defer prog.Close()
	for {
		var violation Octagon_Force_FileSystemEnforcerMap
		var output Log
		action := map[bool]string{true: "allow", false: "deny"}
		it := prog.Iterate()
		var key proc_key
		for it.Next(&key, &violation) {
			err := prog.Delete(&key)
			if err != nil {
				log.Warn("delete failed:", err)
			}
			output.Action = action[violation.Action]
			output.FileName = cString(violation.FileAccessed[:])
			output.Name = cString(violation.RuleName[:])
			output.ContainerID = violation.ContainerID
			tpl, _ := pongo2.FromString(RULEMAP[output.Name].Message)
			output.Message, err = tpl.Execute(pongo2.Context{
				"FileName":    output.FileName,
				"RuleName":    output.Name,
				"SourcePID":   violation.SourcePID,
				"ContainerID": output.ContainerID,
				"Action":      map[bool]string{true: "allow", false: "deny"}[violation.Action],
			})
			if err != nil {
				log.Warn("error making template: ", err)
			}
			bOut, err := json.Marshal(output)
			if err != nil {
				log.Warn("error marshalling json")
			} else {
				fmt.Println(string(bOut))
			}

		}
		if err := it.Err(); err != nil {
			log.Warn("iteration error:", err)
		}

		time.Sleep(1 * time.Second)

	}

}
