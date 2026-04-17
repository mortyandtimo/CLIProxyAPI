package auth

import (
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

func TestUpdateAggregatedAvailability_UnavailableWithoutNextRetryDoesNotBlockAuth(t *testing.T) {
	t.Parallel()

	now := time.Now()
	model := "test-model"
	auth := &Auth{
		ID: "a",
		ModelStates: map[string]*ModelState{
			model: {
				Status:      StatusError,
				Unavailable: true,
			},
		},
	}

	updateAggregatedAvailability(auth, now)

	if auth.Unavailable {
		t.Fatalf("auth.Unavailable = true, want false")
	}
	if !auth.NextRetryAfter.IsZero() {
		t.Fatalf("auth.NextRetryAfter = %v, want zero", auth.NextRetryAfter)
	}
}

func TestUpdateAggregatedAvailability_FutureNextRetryBlocksAuth(t *testing.T) {
	t.Parallel()

	now := time.Now()
	model := "test-model"
	next := now.Add(5 * time.Minute)
	auth := &Auth{
		ID: "a",
		ModelStates: map[string]*ModelState{
			model: {
				Status:         StatusError,
				Unavailable:    true,
				NextRetryAfter: next,
			},
		},
	}

	updateAggregatedAvailability(auth, now)

	if !auth.Unavailable {
		t.Fatalf("auth.Unavailable = false, want true")
	}
	if auth.NextRetryAfter.IsZero() {
		t.Fatalf("auth.NextRetryAfter = zero, want %v", next)
	}
	if auth.NextRetryAfter.Sub(next) > time.Second || next.Sub(auth.NextRetryAfter) > time.Second {
		t.Fatalf("auth.NextRetryAfter = %v, want %v", auth.NextRetryAfter, next)
	}
}

func TestPublishSelectedAuthMetadata_IncludesMatchedPoolGroup(t *testing.T) {
	t.Parallel()

	meta := map[string]any{"auth_file_pools": []string{"alpha"}}
	auth := &Auth{
		ID: "auth-a",
		Metadata: map[string]any{
			"pools":       []any{"alpha", "beta"},
			"pool_groups": map[string]any{"alpha": "gold", "beta": "silver"},
		},
	}

	publishSelectedAuthMetadata(meta, auth)

	if got, _ := meta[cliproxyexecutor.SelectedAuthMetadataKey].(string); got != "auth-a" {
		t.Fatalf("selected auth = %q, want %q", got, "auth-a")
	}
	if got, _ := meta[cliproxyexecutor.SelectedAuthPoolMetadataKey].(string); got != "alpha" {
		t.Fatalf("selected pool = %q, want %q", got, "alpha")
	}
	if got, _ := meta[cliproxyexecutor.SelectedAuthPoolGroupMetadataKey].(string); got != "gold" {
		t.Fatalf("selected pool group = %q, want %q", got, "gold")
	}
}
