package file_system_monitor

import (
	// "bytes"
	// "encoding/binary"
	// "encoding/json"
	// "fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"gopkg.in/yaml.v3"
)

type FileSystemEnforcerMap struct {
	FileAccessed [32]byte
	SourcePID    int32
	ContainerID  uint64
	Action       bool
	RuleName     [32]byte
}

type FileSystemEnforcerRule struct {
	Name     [32]byte
	FileName [32]byte
	Action   bool
}

type Rule struct {
	Name     string `yaml:"name"`
	FileName string `yaml:"filename"`
	Action   string `yaml:"action"`
}

type RuleFile struct {
	Rules []Rule `yaml:"rules"` // array of rule files
}

func UpdateRules(rules []Rule) {
	prog, err := ebpf.LoadPinnedMap("/sys/fs/bpf/file_system_enforcer_rules_pin", nil)
	if err != nil {
		panic(err)
	}
	defer prog.Close()

	for i := 0; i < 100; i++ {
		var newRule FileSystemEnforcerRule

		if i < len(rules) {
			rule := rules[i]
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
	rules = ruleFile.Rules

	return
}

//func Run() {
//	prog, err := ebpf.LoadPinnedMap("/sys/fs/bpf/", nil)
//	if err != nil {
//		return
//	}
//}
