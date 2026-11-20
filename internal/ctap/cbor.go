package ctap

import (
	"errors"
	"fmt"
)

// A deliberately small CBOR reader: only what authenticator data and a COSE key contain (unsigned and negative integers, byte and text strings, maps
// and arrays with definite lengths). Anything else is an error, never a guess.

type cborReader struct {
	b     []byte
	depth int
}

type cborItem struct {
	kind  byte // 0 unsigned, 1 negative, 2 bytes, 3 text, 4 array, 5 map
	n     int64
	bytes []byte
	arr   []cborItem
	m     []cborPair
}

type cborPair struct{ k, v cborItem }

func (r *cborReader) item() (cborItem, error) {
	if r.depth > 8 {
		return cborItem{}, errors.New("cbor: nested too deep")
	}
	if len(r.b) == 0 {
		return cborItem{}, errors.New("cbor: cut short")
	}
	major, info := r.b[0]>>5, r.b[0]&0x1f
	r.b = r.b[1:]
	var arg uint64
	switch {
	case info < 24:
		arg = uint64(info)
	case info >= 24 && info <= 27:
		n := 1 << (info - 24)
		if len(r.b) < n {
			return cborItem{}, errors.New("cbor: cut short")
		}
		for _, c := range r.b[:n] {
			arg = arg<<8 | uint64(c)
		}
		r.b = r.b[n:]
	default:
		return cborItem{}, fmt.Errorf("cbor: unsupported encoding 0x%02x", info)
	}
	switch major {
	case 0, 1:
		if arg > 1<<62 {
			return cborItem{}, errors.New("cbor: integer too large")
		}
		n := int64(arg)
		if major == 1 {
			n = -1 - n
		}
		return cborItem{kind: major, n: n}, nil
	case 2, 3:
		if arg > uint64(len(r.b)) {
			return cborItem{}, errors.New("cbor: string cut short")
		}
		v := r.b[:arg]
		r.b = r.b[arg:]
		return cborItem{kind: major, bytes: v}, nil
	case 4, 5:
		if arg > 64 {
			return cborItem{}, errors.New("cbor: collection too large")
		}
		r.depth++
		defer func() { r.depth-- }()
		it := cborItem{kind: major}
		for i := uint64(0); i < arg; i++ {
			a, err := r.item()
			if err != nil {
				return cborItem{}, err
			}
			if major == 4 {
				it.arr = append(it.arr, a)
				continue
			}
			v, err := r.item()
			if err != nil {
				return cborItem{}, err
			}
			it.m = append(it.m, cborPair{a, v})
		}
		return it, nil
	}
	return cborItem{}, fmt.Errorf("cbor: unsupported major type %d", major)
}

func (it cborItem) get(key int64) (cborItem, bool) {
	for _, p := range it.m {
		if (p.k.kind == 0 || p.k.kind == 1) && p.k.n == key {
			return p.v, true
		}
	}
	return cborItem{}, false
}

// unwrapByteString reads b as exactly one CBOR byte string and returns its content. libfido2 prints authenticator data in this form.
func unwrapByteString(b []byte) ([]byte, error) {
	r := &cborReader{b: b}
	it, err := r.item()
	if err != nil || it.kind != 2 || len(r.b) != 0 {
		return nil, errors.New("ctap: authenticator data is not one CBOR byte string")
	}
	return it.bytes, nil
}
