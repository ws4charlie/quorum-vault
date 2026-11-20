package broker

import (
	"encoding/json"

	"github.com/miekg/pkcs11"
)

func jsonMarshal(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

// aliases so the teesim rig can read key attributes without a second import of the pkcs11 package name clashing with the helper's receiver
type (
	pkcs11SessionHandle = pkcs11.SessionHandle
	pkcs11Attribute     = pkcs11.Attribute
)

var pkcs11NewAttribute = pkcs11.NewAttribute

const pkcs11CKA_EXTRACTABLE, pkcs11CKA_SENSITIVE = pkcs11.CKA_EXTRACTABLE, pkcs11.CKA_SENSITIVE
