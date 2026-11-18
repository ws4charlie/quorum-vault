#!/bin/bash
# One-shot job: the access rules of the business Kafka, made with the admin certificate (a superuser). Redpanda takes the principal from the client
# certificate's common name (the service name; the mapping rule in docker-compose.yml), so these rules are "which service name may do what". A name with no rule here can
# connect (its certificate is from the business authority) and can do nothing.
set -euo pipefail
X=(-X brokers=redpanda:9092 -X tls.enabled=true -X tls.ca=/admin/ca.crt -X tls.cert=/admin/tls.crt -X tls.key=/admin/tls.key)
acl() { rpk security acl create "${X[@]}" "$@" >/dev/null; }
# the relay publishes every outbox topic (qv.*) and creates the ones that do not exist yet
acl --allow-principal User:relay --operation write,describe,create --topic qv. --resource-pattern-type prefixed
acl --allow-principal User:relay --operation idempotent_write --cluster
# the signing zone's programs publish their audit chain heads, through their business-issued link certificates, and nothing else
for who in gateway-link cosigner-link; do
  acl --allow-principal "User:$who" --operation write,describe,create --topic qv.audit.heads
  acl --allow-principal "User:$who" --operation idempotent_write --cluster
done
# the archiver reads the heads, in its own consumer group
acl --allow-principal User:archiver --operation read,describe --topic qv.audit.heads
acl --allow-principal User:archiver --operation read,describe --group qv-anchor-archiver --resource-pattern-type prefixed
echo "redpanda acls ready"
