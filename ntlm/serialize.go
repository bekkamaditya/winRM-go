package ntlm

import (
	"bytes"
	"encoding/base64"
)

type Serializable interface {
	WriteBytesToBuffer(*bytes.Buffer)
}

func Serialize(sz Serializable) []byte {
	var buf = &bytes.Buffer{}
	sz.WriteBytesToBuffer(buf)
	return buf.Bytes()
}

func SerializeBytesToBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
