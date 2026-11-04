package infratest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	temporalAddr = "127.0.0.1:7233"
	kafkaAddr    = "127.0.0.1:19092"
)

func requireInfra(t *testing.T) {
	t.Helper()
	if os.Getenv("QV_REQUIRE_INFRA") != "1" {
		t.Skip("QV_REQUIRE_INFRA != 1 (`make infra-up test-infra`)")
	}
}

func Greet(ctx workflow.Context, name string) (string, error) {
	return "hello " + name, nil
}

// A one-step workflow through a real worker against the dev Temporal server.
func TestTemporalWorkflow(t *testing.T) {
	requireInfra(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	const namespace = "default"
	ns, err := client.NewNamespaceClient(client.Options{HostPort: temporalAddr})
	if err != nil {
		t.Fatalf("namespace client: %v", err)
	}
	defer ns.Close()
	// The dev server starts without a namespace: create it (idempotent).
	err = ns.Register(ctx, &workflowservice.RegisterNamespaceRequest{
		Namespace:                        namespace,
		WorkflowExecutionRetentionPeriod: durationpb.New(24 * time.Hour),
	})
	var exists *serviceerror.NamespaceAlreadyExists
	if err != nil && !errors.As(err, &exists) {
		t.Fatalf("register namespace: %v", err)
	}

	c, err := client.DialContext(ctx, client.Options{HostPort: temporalAddr, Namespace: namespace})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	queue := fmt.Sprintf("qv-smoke-%d", time.Now().UnixNano())
	w := worker.New(c, queue, worker.Options{})
	w.RegisterWorkflow(Greet)
	if err := w.Start(); err != nil {
		t.Fatalf("worker: %v", err)
	}
	defer w.Stop()

	// The namespace may take a moment to become visible after registration.
	var got string
	deadline := time.Now().Add(60 * time.Second)
	for {
		run, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{TaskQueue: queue}, Greet, "quorum")
		if err == nil {
			err = run.Get(ctx, &got)
		}
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("workflow: %v", err)
		}
		time.Sleep(time.Second)
	}
	if got != "hello quorum" {
		t.Errorf("result = %q, want %q", got, "hello quorum")
	}
}

// Produce one message to Redpanda and consume it back.
func TestRedpandaRoundTrip(t *testing.T) {
	requireInfra(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	topic := fmt.Sprintf("qv.smoke.%d", time.Now().UnixNano())
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(kafkaAddr),
		kgo.AllowAutoTopicCreation(),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		t.Fatalf("kafka client: %v", err)
	}
	defer cl.Close()

	rec := &kgo.Record{Topic: topic, Key: []byte("k"), Value: []byte("v")}
	if err := cl.ProduceSync(ctx, rec).FirstErr(); err != nil {
		t.Fatalf("produce: %v", err)
	}
	for {
		fetches := cl.PollFetches(ctx)
		if err := ctx.Err(); err != nil {
			t.Fatalf("consume: %v (fetch errors: %v)", err, fetches.Errors())
		}
		var found bool
		fetches.EachRecord(func(r *kgo.Record) {
			if string(r.Key) == "k" && string(r.Value) == "v" {
				found = true
			}
		})
		if found {
			return
		}
	}
}
