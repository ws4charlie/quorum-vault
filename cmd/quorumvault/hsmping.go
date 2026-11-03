package main

import (
	"fmt"

	"github.com/miekg/pkcs11"
)

// hsmPing checks the session is alive and still logged in.
func hsmPing(p *pkcs11.Ctx, s pkcs11.SessionHandle) error {
	info, err := p.GetSessionInfo(s)
	if err != nil {
		return err
	}
	if info.State != pkcs11.CKS_RW_USER_FUNCTIONS {
		return fmt.Errorf("session not logged in (state %d)", info.State)
	}
	return nil
}
