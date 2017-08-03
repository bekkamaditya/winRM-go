package ntlm

import (
	"bytes"
	//	"fmt"
)

type NegotiateMessage struct {
	Signature   string
	Type        Uint32LE
	Flag        NegotiateFlag
	Domain      SecurityBuffer
	WorkStation SecurityBuffer
	OSVersion   Uint32LE
	fullPayload []byte
}

func ParseNegotiateMessage(p []byte) (NegotiateMessage, error) {
	var nm NegotiateMessage
	var ci int
	var err error
	if len(p) < 32 {
		return nm, MalformedBytesError
	}
	nm.Signature = string(p[ci : ci+8])
	if nm.Signature != NTLMSig {
		return nm, MalformedBytesError
	}
	//fmt.Println(nm.Signature)
	ci += 8
	nm.Type, err = ParseUint32LE(p[ci : ci+4])
	if err != nil {
		return nm, err
	}
	//fmt.Println(nm.Type)
	ci += 4
	if nm.Type != 1 {
		return nm, MalformedBytesError
	}
	nm.Flag, err = ParseNegotiateFlag(p[ci : ci+4])
	if err != nil {
		return nm, err
	}
	//fmt.Println(nm.Flag)
	ci += 4
	nm.Domain, err = ParseSecurityBuffer(p[ci : ci+8])
	if err != nil {
		return nm, err
	}
	//fmt.Printf("dmoain %+v", nm.Domain)
	ci += 8
	if nm.Domain.Len > 0 {
		nm.Domain.Value = p[nm.Domain.OffSet : nm.Domain.OffSet+Uint32LE(nm.Domain.MaxLen)]
	}
	nm.WorkStation, err = ParseSecurityBuffer(p[ci : ci+8])
	//fmt.Printf("workstation %+v", nm.WorkStation)
	if err != nil {
		return nm, err
	}
	ci += 8
	if nm.WorkStation.Len > 0 {
		nm.WorkStation.Value = p[nm.WorkStation.OffSet : nm.WorkStation.OffSet+Uint32LE(nm.WorkStation.MaxLen)]
	}
	nm.fullPayload = p
	return nm, nil
}

func (nm NegotiateMessage) WriteBytesToBuffer(buf *bytes.Buffer) {
	var payload = &bytes.Buffer{}
	buf.WriteString(nm.Signature)
	nm.Type.WriteBytesToBuffer(buf)
	nm.Flag.WriteBytesToBuffer(buf)
	nm.Domain.OffSet = 32
	nm.Domain.WriteBytesToBuffer(buf, payload)
	nm.WorkStation.OffSet = 32 + Uint32LE(payload.Len())
	nm.WorkStation.WriteBytesToBuffer(buf, payload)
	buf.Write(payload.Bytes())
}

func NewNegotiateMessage(domain string, workstation string) NegotiateMessage {
	var nm NegotiateMessage
	nm.Signature = NTLMSig
	nm.Type = 0x01
	nm.Flag = DefaultFlags[0x01]
	//fmt.Printf("flg is %s", nm.Flag)
	dBytes := utf8ToUtf16(domain)
	nm.Domain = SecurityBuffer{
		Len:    Uint16LE(len(dBytes)),
		MaxLen: Uint16LE(len(dBytes)),
		Value:  dBytes,
	}
	wsBytes := utf8ToUtf16(workstation)
	nm.Domain = SecurityBuffer{
		Len:    Uint16LE(len(wsBytes)),
		MaxLen: Uint16LE(len(wsBytes)),
		Value:  wsBytes,
	}
	return nm
}
