package pki

import "encoding/pem"

// pemDecode returns the DER of the next CERTIFICATE block, skipping other blocks.
func pemDecode(b []byte) (der, rest []byte) {
	for {
		blk, r := pem.Decode(b)
		if blk == nil {
			return nil, nil
		}
		if blk.Type == "CERTIFICATE" {
			return blk.Bytes, r
		}
		b = r
	}
}
