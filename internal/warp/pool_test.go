package warp

import (
	"context"
	"testing"
)

func TestNewWithOptionsRejectsInvalidMTUBeforeRegistration(t *testing.T) {
	for _, mtu := range []int{MinMTU - 1, MaxMTU + 1} {
		_, err := NewWithOptions(context.Background(), nil, Options{MTU: mtu})
		if err == nil {
			t.Fatalf("NewWithOptions() accepted MTU %d", mtu)
		}
	}
}
