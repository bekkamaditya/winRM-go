package ntlm

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const NTLMSig = "NTLMSSP\000"

type Uint16LE uint16

var MalformedBytesError = fmt.Errorf("Malformed bytes")

func (u Uint16LE) WriteBytesToBuffer(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint16(u))
}

func ParseUint16LE(p []byte) (Uint16LE, error) {
	if len(p) == 2 {
		return Uint16LE(binary.LittleEndian.Uint16(p)), nil
	}
	return 0, MalformedBytesError
}

type Uint32LE uint32

func (u Uint32LE) WriteBytesToBuffer(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint32(u))
}

func ParseUint32LE(p []byte) (Uint32LE, error) {
	if len(p) == 4 {
		return Uint32LE(binary.LittleEndian.Uint32(p)), nil
	}
	return 0, MalformedBytesError
}

type Uint64LE uint64

func (u Uint64LE) WriteBytesToBuffer(buf *bytes.Buffer) {
	binary.Write(buf, binary.LittleEndian, uint64(u))
}
func ParseUint64LE(p []byte) (Uint64LE, error) {
	if len(p) == 8 {
		return Uint64LE(binary.LittleEndian.Uint64(p)), nil
	}
	return 0, MalformedBytesError
}

type Blob struct {
	Signature  Uint32LE
	Reserved   Uint32LE
	Timestamp  Uint64LE
	Challenge  []byte
	Unknown    Uint32LE
	TargetInfo []byte
	Unknown2   Uint32LE
}

func (b Blob) WriteBytesToBuffer(buf *bytes.Buffer) {
	b.Signature.WriteBytesToBuffer(buf)
	b.Reserved.WriteBytesToBuffer(buf)
	b.Timestamp.WriteBytesToBuffer(buf)
	buf.Write(b.Challenge)
	b.Unknown.WriteBytesToBuffer(buf)
	buf.Write(b.TargetInfo)
	b.Unknown2.WriteBytesToBuffer(buf)
}

func ParseBlob(p []byte, si int) (Blob, error) {
	b := Blob{}
	var ci int
	var err error
	if len(p) > 28 {
		b.TargetInfo = p[28 : len(p)-5]
		b.Unknown2 = 0
		p = p[:28]
	}
	if len(p) != 28 {
		return b, MalformedBytesError
	}
	b.Signature, err = ParseUint32LE(p[ci : ci+4])
	if err != nil {
		return b, err
	}
	ci += 4
	b.Reserved = 0
	ci += 4
	b.Timestamp, err = ParseUint64LE(p[ci : ci+8])
	if err != nil {
		return b, err
	}
	ci += 8
	b.Challenge = p[ci : ci+8]
	ci += 8
	b.Unknown2 = 0
	return b, nil
}

func NewBlob() Blob {
	return Blob{
		Signature: 0x00000101,
	}
}
