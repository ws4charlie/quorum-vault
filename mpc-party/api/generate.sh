#!/usr/bin/env bash
# Regenerate mpcparty/v1/*.pb.go. Generator versions (recorded in the generated headers):
#   protoc            libprotoc 25.1 (pip grpcio-tools==1.62.3, throwaway venv; any protoc >= 25 works)
#   protoc-gen-go     v1.36.12  (2026-08-10)  go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
#   protoc-gen-go-grpc v1.6.1   (2026-02-04)  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1
# Runtime: google.golang.org/grpc v1.84.0 (2026-09-17), google.golang.org/protobuf v1.36.12 (see go.mod).
set -euo pipefail
cd "$(dirname "$0")"
PROTOC="${PROTOC:-protoc}"
PATH="$(go env GOPATH)/bin:$PATH" $PROTOC -I . --go_out=. --go_opt=paths=source_relative \
  --go-grpc_out=. --go-grpc_opt=paths=source_relative mpcparty/v1/mpcparty.proto
