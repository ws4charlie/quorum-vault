package infratest

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"go.temporal.io/sdk/client"

	"github.com/ws4charlie/quorum-vault/internal/pki"
	"github.com/ws4charlie/quorum-vault/internal/pki/pkitest"
)

// The business Kafka and the Temporal frontend take TLS with a client certificate of the business authority and nothing else. For Kafka, what a
// name may do is set by ACLs (deploy/redpanda/acl.sh). Needs `make infra-up` (QV_REQUIRE_INFRA=1).

func produce(tc *tls.Config, topic string) error {
	opts := []kgo.Opt{kgo.SeedBrokers(kafkaAddr), kgo.AllowAutoTopicCreation(), kgo.RecordDeliveryTimeout(8 * time.Second), kgo.DialTimeout(5 * time.Second), kgo.RequestRetries(1)}
	if tc != nil {
		opts = append(opts, kgo.DialTLSConfig(tc))
	}
	cl, err := kgo.NewClient(opts...)
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return cl.ProduceSync(ctx, &kgo.Record{Topic: topic, Key: []byte("k"), Value: []byte("v")}).FirstErr()
}

func consumeOnce(tc *tls.Config, topic, group string) error {
	cl, err := kgo.NewClient(kgo.SeedBrokers(kafkaAddr), kgo.DialTLSConfig(tc), kgo.ConsumerGroup(group), kgo.ConsumeTopics(topic), kgo.DialTimeout(5*time.Second))
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	f := cl.PollFetches(ctx)
	if errs := f.Errors(); len(errs) > 0 && ctx.Err() == nil {
		return errs[0].Err
	}
	for _, e := range f.Errors() {
		if strings.Contains(e.Err.Error(), "AUTHORIZATION") {
			return e.Err
		}
	}
	return nil
}

func TestKafkaRefusesWhatItShould(t *testing.T) {
	requireInfra(t)
	t.Run("a client without a certificate", func(t *testing.T) {
		tc := pkitest.ClientTLS(pki.ZoneBusiness, "admin", "", "kafka")
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
		err := produce(tc, "qv.mtls.none")
		if err == nil {
			t.Fatal("a client without a certificate produced")
		}
		t.Logf("refused, as it must be: %.160v", err)
	})
	t.Run("a plain connection", func(t *testing.T) {
		err := produce(nil, "qv.mtls.plain")
		if err == nil {
			t.Fatal("a plain connection produced")
		}
		t.Logf("refused, as it must be: %.160v", err)
	})
	t.Run("the signing zone's certificate", func(t *testing.T) {
		tc := pkitest.ClientTLS(pki.ZoneSigning, "gateway", "", "kafka")
		tc.VerifyConnection = nil // its own server check would refuse first (it trusts the signing authority); the refusal tested is the broker's
		tc.InsecureSkipVerify = true
		err := produce(tc, "qv.mtls.otherzone")
		if err == nil {
			t.Fatal("a signing-zone certificate produced")
		}
		t.Logf("refused, as it must be: %.160v", err)
	})
	t.Run("the right authority, a name with no rule", func(t *testing.T) {
		err := produce(pkitest.ClientTLS(pki.ZoneBusiness, "guardian", "", "kafka"), "qv.audit.heads")
		if err == nil || !strings.Contains(err.Error(), "AUTHORIZATION") {
			t.Fatalf("a name without an ACL produced (or failed otherwise): %v", err)
		}
		t.Logf("refused, as it must be: %.160v", err)
	})
	t.Run("a link name may publish heads and nothing else", func(t *testing.T) {
		gw := pkitest.ClientTLS(pki.ZoneBusiness, "gateway-link", "", "kafka")
		if err := produce(gw, "qv.audit.heads"); err != nil {
			t.Fatalf("the gateway's link certificate could not publish a head: %v", err)
		}
		if err := produce(gw, "qv.withdrawals"); err == nil || !strings.Contains(err.Error(), "AUTHORIZATION") {
			t.Fatalf("the gateway's link certificate published to the outbox topics: %v", err)
		}
		if err := produce(pkitest.ClientTLS(pki.ZoneBusiness, "cosigner-link", "", "kafka"), "qv.audit.heads"); err != nil {
			t.Fatalf("the cosigner's link certificate could not publish a head: %v", err)
		}
	})
	t.Run("the relay publishes outbox topics; the archiver only reads heads", func(t *testing.T) {
		topic := fmt.Sprintf("qv.mtls.relay.%d", time.Now().UnixNano())
		if err := produce(pkitest.ClientTLS(pki.ZoneBusiness, "relay", "", "kafka"), topic); err != nil {
			t.Fatalf("the relay could not publish: %v", err)
		}
		ar := pkitest.ClientTLS(pki.ZoneBusiness, "archiver", "", "kafka")
		if err := produce(ar, "qv.audit.heads"); err == nil || !strings.Contains(err.Error(), "AUTHORIZATION") {
			t.Fatalf("the archiver published: %v", err)
		}
		if err := consumeOnce(ar, "qv.audit.heads", "qv-anchor-archiver-mtlstest"); err != nil {
			t.Fatalf("the archiver could not read the heads: %v", err)
		}
	})
	t.Run("the client refuses a broker with another name", func(t *testing.T) {
		err := produce(pkitest.ClientTLS(pki.ZoneBusiness, "admin", "", "keycloak"), "qv.mtls.name")
		if err == nil {
			t.Fatal("the client accepted a broker whose name is not on its list")
		}
	})
}

func TestTemporalRefusesWhatItShould(t *testing.T) {
	requireInfra(t)
	list := func(tc *tls.Config) error {
		opts := client.Options{HostPort: temporalAddr, ConnectionOptions: client.ConnectionOptions{TLS: tc}}
		if tc == nil {
			opts.ConnectionOptions = client.ConnectionOptions{}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		ns, err := client.NewNamespaceClient(opts)
		if err != nil {
			return err
		}
		defer ns.Close()
		_, err = ns.Describe(ctx, "default")
		return err
	}
	// the names that may call are listed in the gate in front of the frontend (deploy/temporal-gate/nginx.conf)
	t.Run("the names on the list work", func(t *testing.T) {
		for _, who := range []string{"worker", "core", "admin"} {
			if err := list(pkitest.ClientTLS(pki.ZoneBusiness, who, "temporal", "temporal")); err != nil && !strings.Contains(err.Error(), "not found") {
				t.Errorf("%s was refused: %v", who, err)
			}
		}
	})
	t.Run("the right authority, a name that is not on the list", func(t *testing.T) {
		for _, who := range []string{"relay", "archiver", "guardian", "gateway-link", "cosigner-link"} {
			err := list(pkitest.ClientTLS(pki.ZoneBusiness, who, "temporal", "temporal"))
			if err == nil || strings.Contains(err.Error(), "not found") {
				t.Errorf("%s (a business certificate not on the list) was served: %v", who, err)
				continue
			}
			t.Logf("refused, as it must be: %s: %.140v", who, err)
		}
	})
	t.Run("a client without a certificate", func(t *testing.T) {
		tc := pkitest.ClientTLS(pki.ZoneBusiness, "worker", "temporal", "temporal")
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
		if err := list(tc); err == nil {
			t.Fatal("a client without a certificate was served")
		} else {
			t.Logf("refused, as it must be: %.160v", err)
		}
	})
	t.Run("a plain connection", func(t *testing.T) {
		if err := list(nil); err == nil {
			t.Fatal("a plain connection was served")
		} else {
			t.Logf("refused, as it must be: %.160v", err)
		}
	})
	t.Run("the signing zone's certificate", func(t *testing.T) {
		tc := pkitest.ClientTLS(pki.ZoneSigning, "gateway", "temporal")
		tc.VerifyConnection = nil
		tc.InsecureSkipVerify = true
		if err := list(tc); err == nil {
			t.Fatal("a signing-zone certificate was served")
		} else {
			t.Logf("refused, as it must be: %.160v", err)
		}
	})
	t.Run("the client refuses a frontend with another name", func(t *testing.T) {
		if err := list(pkitest.ClientTLS(pki.ZoneBusiness, "worker", "temporal", "kafka")); err == nil {
			t.Fatal("the client accepted a server whose name is not on its list")
		}
	})
}

// Rotation: the servers' certificates are replaced while they run; new connections get the new certificate, nothing restarts. Redpanda re-reads its
// files by itself; Temporal does every TEMPORAL_TLS_REFRESH_INTERVAL (1 minute in compose), so this waits up to two.
func TestServersFollowRotatedCertificates(t *testing.T) {
	requireInfra(t)
	serial := func(addr, name string) (string, error) {
		tc := pkitest.ClientTLS(pki.ZoneBusiness, "admin", "")
		tc.ServerName = name
		d := &tls.Dialer{Config: tc}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return "", err
		}
		defer c.Close()
		return c.(*tls.Conn).ConnectionState().PeerCertificates[0].SerialNumber.String(), nil
	}
	for _, s := range []struct{ svc, addr, name string }{{"kafka", kafkaAddr, "redpanda"}, {"temporal", temporalAddr, "temporal"}} {
		before, err := serial(s.addr, s.name)
		if err != nil {
			t.Fatalf("%s: %v", s.svc, err)
		}
		pkitest.Reissue(t, pki.ZoneBusiness, s.svc)
		deadline := time.Now().Add(2*time.Minute + 20*time.Second)
		for {
			now, err := serial(s.addr, s.name)
			if err == nil && now != before {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s still serves the old certificate (%s) after the files were replaced (last error %v)", s.svc, before, err)
			}
			time.Sleep(3 * time.Second)
		}
	}
}
