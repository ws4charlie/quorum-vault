package attest

// RecipientKeyMaker is implemented by a releaser that needs the key inside the evidence to be of its own kind. The broker of this repository takes an
// X25519 key (NewReleaseKey, SealTo, OpenFrom); AWS KMS takes only an RSA key and answers with a CMS EnvelopedData (RSAES_OAEP_SHA_256) [KMS-API].
// The attested sealer asks the releaser for the key pair when it implements this interface and uses the default otherwise.
type RecipientKeyMaker interface {
	// NewRecipient makes the key pair for one exchange. pubDER goes into the evidence's public_key; open decrypts the Sealed field of a released key.
	// The private key lives only in the closure, in this process.
	NewRecipient() (pubDER []byte, open func(aad, sealed []byte) ([]byte, error), err error)
}
