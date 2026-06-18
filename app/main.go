package main

import (
	"os"
	"os/signal"

	LOG "github.com/charmbracelet/log"

	// bpf maps and functions
	"github.com/Ceald1/octagon-force/app/file_system_monitor"
)

func main() {
	LOG.Info("starting....")
	fileSystemMonitorRules := file_system_monitor.ParseRules()
	file_system_monitor.UpdateRules(fileSystemMonitorRules)
	go file_system_monitor.Run()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	for {
		select {
		case <-sigChan:
			return
		}
	}
}
