package network

import (
	"fmt"
	"structs"

	"github.com/Ceald1/octagon-force/app/outputs"
	"github.com/Ceald1/octagon-force/app/outputs/utils"
	"github.com/charmbracelet/log"
	"github.com/cilium/ebpf"
	"net"
)

type networkNetworkEnforcerRules struct {
	_      structs.HostLayout
	Name   [32]int8
	Host   [256]int8
	Action bool
}

type NetworkEvent struct {
	ContainerID uint64   // 8 bytes (offset 0)
	SourcePID   int32    // 4 bytes (offset 8)
	Family      uint16   // 2 bytes (offset 12)
	DPort       uint16   // 2 bytes (offset 14)
	SAddrV4     [4]byte  // 4 bytes (offset 16) - Source IPv4
	DAddrV4     [4]byte  // 4 bytes (offset 20) - Dest IPv4
	SAddrV6     [16]byte // 16 bytes (offset 24) - Source IPv6
	DAddrV6     [16]byte // 16 bytes (offset 40) - Dest IPv6
	EventName   [24]int8 // 24 bytes (offset 56)
} // Total size = 80 bytes

func (e *NetworkEvent) SAddr() net.IP {
	if e.Family == 2 {
		return net.IP(e.SAddrV4[:])
	} else if e.Family == 10 {
		return net.IP(e.SAddrV6[:])
	}
	return nil
}

// DAddr returns the destination IP as a standard net.IP based on Family
func (e *NetworkEvent) DAddr() net.IP {
	if e.Family == 2 { // AF_INET
		return net.IP(e.DAddrV4[:])
	} else if e.Family == 10 { // AF_INET6
		return net.IP(e.DAddrV6[:])
	}
	return nil
}

// DestinationPort returns the port in host byte order
func (e *NetworkEvent) DestinationPort() uint16 {
	return (e.DPort<<8)&0xFF00 | (e.DPort >> 8)
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
	Pid       uint32
	_         [4]byte
	StartTime uint64
}

//	type Output struct {
//		SourceID  uint64
//		EventName string
//	}
func Run() {
	prog, err := ebpf.LoadPinnedMap("/sys/fs/bpf/octagon_force/network/octagon_force_network_event_map_pin", nil)
	if err != nil {
		log.Warn("error loading pinned map for network observing.\n")
		return
	}
	log.Info("starting network observing")
	defer prog.Close()
	for {
		var event NetworkEvent
		var key networkProcKey
		var outNetwork utils.NetworkEvent
		it := prog.Iterate()
		for it.Next(&key, &event) {
			err := prog.Delete(&key)
			if err != nil {
				log.Warn("delete failed: ", err.Error())
			}

			outNetwork.ContainerID = fmt.Sprintf("%d", event.ContainerID)
			outNetwork.ContainerPID = fmt.Sprintf("%d", event.SourcePID)
			outNetwork.Source = event.SAddr().String()
			outNetwork.Destination = event.DAddr().String()
			outNetwork.EventType = event.GetEventName()
			outLog := utils.Output[utils.NetworkEvent]{
				Data: outNetwork,
			}
			podname, ns, err := outLog.GetPod()
			if err != nil {
				log.Warn(err.Error())
				continue // ignore pod
			} else {
				outLog.Source = podname
				outLog.Data.Namespace = ns
			}
			err = outputs.NewLokiPayload(outLog)
			if err != nil {
				log.Warn(err.Error())
			}

			// log.Info(fmt.Sprintf("container pid: %d performed: %s from %s to: %s\n", event.SourcePID, out.EventName, event.SAddr().String(), event.DAddr().String()))

		}

	}

}
