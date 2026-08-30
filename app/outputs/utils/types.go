package utils

type NetworkEvent struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	EventType   string `json:"event_type"`
	ContainerID string `json:"containerID"`
	PID         string `json:"PID"`
	ParentPID   string `json:"parentPID"`
	Namespace   string `json:"namespace"`
}

type SigmaEvent struct {
	Name        string `json:"name"`
	Level       string `json:"action"`
	Message     string `json:"message"`
	ContainerID string `json:"containerID"`
	PID         string `json:"PID"`
	ParentPID   string `json:"parentPID"`
	Namespace   string `json:"namespace"`
}

type FileSystemEvent struct {
	Name        string `json:"name"`
	FileName    string `json:"filename"`
	Action      string `json:"action"`
	Message     string `json:"message"`
	ContainerID string `json:"containerID"`
	PID         string `json:"PID"`
	ParentPID   string `json:"parentPID"`
	Namespace   string `json:"namespace"`
}
