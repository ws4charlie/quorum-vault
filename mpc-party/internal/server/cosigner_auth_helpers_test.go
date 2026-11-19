package server_test

import (
	"io"
	"log"
	"net"
)

func netListenUnix(path string) (net.Listener, error) { return net.Listen("unix", path) }

func discardLog() *log.Logger { return log.New(io.Discard, "", 0) }
