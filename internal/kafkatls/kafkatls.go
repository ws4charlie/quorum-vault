// Package kafkatls gives Kafka clients (franz-go) the TLS settings of this system: the client presents its certificate, and the brokers' certificate is
// checked against the zone's authority and, when a list is given, against the broker names allowed. The broker decides what the client's name may do
// (docker-compose.yml, deploy/redpanda: ACLs by certificate name).
package kafkatls

import (
	"errors"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ws4charlie/quorum-vault/internal/pki"
)

// BrokerNames is who may answer as a broker: the Kafka endpoint of the business zone.
var BrokerNames = pki.Allow{pki.ID(pki.ZoneBusiness, "kafka")}

// Options returns the client options for src. src is nil only when pki.PlaintextAllowed (development); otherwise a nil src is an error, so a
// service never talks to Kafka in the clear by accident.
func Options(src *pki.Source) ([]kgo.Opt, error) {
	if src == nil {
		if pki.PlaintextAllowed() {
			return nil, nil
		}
		return nil, errors.New("kafka: TLS is required (certificate flags missing); plain text is for a development machine only (QV_ALLOW_PLAINTEXT=1, QV_ENV=dev)")
	}
	return []kgo.Opt{kgo.DialTLSConfig(src.ClientConfig("", BrokerNames))}, nil
}
