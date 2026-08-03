package main

import (
	"os"
	"os/signal"

	LOG "github.com/charmbracelet/log"

	// bpf maps and functions
	"github.com/Ceald1/octagon-force/app/file_system_monitor"
	n "github.com/Ceald1/octagon-force/app/network"
	"github.com/Ceald1/octagon-force/app/sigma"
)

func main() {
	LOG.Info("starting....")
	fileSystemMonitorRules := file_system_monitor.ParseRules()
	file_system_monitor.UpdateRules(fileSystemMonitorRules)
	go file_system_monitor.Run()

	sigmaRules, err := sigma.GetRules()
	if err != nil {
		panic(err)
	}
	go sigma.Exec_Run(sigmaRules)
	go sigma.Write_Run(sigmaRules)
	//go sigma.Network_Run(sigmaRules)
	go n.Run()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	for {
		select {
		case <-sigChan:
			return
		}
	}
}
