package ntlm

import (
	"bytes"
)

type SecurityBuffer struct {
	Len    Uint16LE
	MaxLen Uint16LE
	OffSet Uint32LE
	Value  []byte
}

func (sb SecurityBuffer) WriteBytesToBuffer(buf *bytes.Buffer, payload *bytes.Buffer) {
	sb.Len = Uint16LE(len(sb.Value))
	sb.MaxLen = Uint16LE(len(sb.Value))
	sb.Len.WriteBytesToBuffer(buf)
	sb.MaxLen.WriteBytesToBuffer(buf)
	sb.OffSet.WriteBytesToBuffer(buf)
	payload.Write(sb.Value)
}

func ParseSecurityBuffer(p []byte) (SecurityBuffer, error) {
	var sb SecurityBuffer
	var ci int
	var err error
	if len(p) < 8 {
		return sb, MalformedBytesError
	}
	sb.Len, err = ParseUint16LE(p[ci : ci+2])
	if err != nil {
		return sb, err
	}
	ci += 2
	sb.MaxLen, err = ParseUint16LE(p[ci : ci+2])
	if err != nil {
		return sb, err
	}
	ci += 2
	sb.OffSet, err = ParseUint32LE(p[ci : ci+4])
	if err != nil {
		return sb, err
	}
	ci += 4
	return sb, nil
}
