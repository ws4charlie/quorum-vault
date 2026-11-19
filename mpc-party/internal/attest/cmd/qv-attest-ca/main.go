// Command qv-attest-ca makes the development test CA for the simulated Nitro attester (root and intermediate certificates and the
// intermediate key) under the dev PKI directory. It exists only in a build with -tags teesim; scripts/pki.sh builds it that way. The files are
// never committed. Production gets no such CA: its trust root is the vendor's.
//
//	qv-attest-ca [-dir data/pki/tee] [-ttl 2160h]   keeps an existing CA that is valid for more than a day
package main

import "os"

func main() { os.Exit(run(os.Args[1:])) }
