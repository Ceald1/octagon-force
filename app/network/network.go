//go:build mips || mips64 || ppc64 || s390x

package network

import (
	"fmt"
	"structs"

	"github.com/charmbracelet/log"
	"github.com/cilium/ebpf"
)

type networkNetworkEnforcerRules struct {
	_      structs.HostLayout
	Name   [32]int8
	Host   [256]int8
	Action bool
}

type NetworkEvent struct {
	SourcePID   int32
	_           [4]byte // Automated alignment padding
	ContainerID uint64
	EventName   [30]int8
	_           [2]byte // Automated trailing padding
}

func (n *NetworkEvent) GetEventName() string {
	buf := make([]byte, 0, len(n.EventName))
	for _, b := range n.EventName {
		if b == 0 { // Stop at the null terminator
			break
		}
		buf = append(buf, byte(b))
	}
	return string(buf)
}

type networkProcKey struct {
	_         structs.HostLayout
	Pid       uint32
	_         [4]byte
	StartTime uint64
}
type Output struct {
	SourceID  uint64
	EventName string
}

func Run() {
	prog, err := ebpf.LoadPinnedMap("/sys/fs/bpf/octagon_force/network/octagon_force_network_event_map_pin", nil)
	if err != nil {
		log.Warn("error loading pinned map for network observing.\n")
		return
	}
	defer prog.Close()
	for {
		var event NetworkEvent
		var key networkProcKey
		var out Output
		it := prog.Iterate()
		for it.Next(&key, &event) {
			err := prog.Delete(&key)
			if err != nil {
				log.Warn("delete failed: ", err.Error())
			}
			out.EventName = event.GetEventName()
			out.SourceID = event.ContainerID
			log.Info(fmt.Sprintf("container: %u performed: %s \n", out.SourceID, out.EventName))

		}

	}

}
