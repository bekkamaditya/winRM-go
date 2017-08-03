package ntlm

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestNegotiateLoad(t *testing.T) {
	b64 := "TlRMTVNTUAABAAAAB4IIABYAFgAgAAAAAAAAADYAAAByAHUAZAByAGEALgBsAG8AYwBhAGwA"
	b, _ := base64.StdEncoding.DecodeString(b64)
	nm, er := ParseNegotiateMessage(b)
	fmt.Println("nm", nm)
	fmt.Println(er)
}
