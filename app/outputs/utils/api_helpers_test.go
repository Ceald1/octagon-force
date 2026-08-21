package utils_test

import (
	"testing"

	Outputs "github.com/Ceald1/octagon-force/app/outputs/utils"
)

func TestGetPod_UnmappedPID(t *testing.T) {

	testEvent := Outputs.NetworkEvent{ContainerPID: "21090"}
	output := Outputs.Output[Outputs.NetworkEvent]{
		Data: testEvent,
	}

	podName, err := output.GetPod()
	if err != nil {
		t.Logf("PID resolution failed as expected for non-existent PID: %v", err)
		return
	}

	t.Logf("Successfully matched pod name: %s", podName)
}
