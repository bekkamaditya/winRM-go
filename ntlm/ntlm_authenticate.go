package ntlm

import (
	"bytes"
)

type AuthenticateMessage struct {
	Signature    string
	Type         Uint32LE
	LMResponse   SecurityBuffer
	NTLMResponse SecurityBuffer
	Domain       SecurityBuffer
	User         SecurityBuffer
	WorkStation  SecurityBuffer
	SessionKey   SecurityBuffer
	Flag         NegotiateFlag
}

func NewAuthenticateMessage() AuthenticateMessage {
	am := AuthenticateMessage{
		Signature: NTLMSig,
		Type:      0x003,
	}
	return am
}

func (am AuthenticateMessage) WriteBytesToBuffer(buf *bytes.Buffer) {
	buf.WriteString(am.Signature)
	am.Type.WriteBytesToBuffer(buf)
	var payloadBuf = &bytes.Buffer{}
	am.LMResponse.OffSet = 64
	am.LMResponse.WriteBytesToBuffer(buf, payloadBuf)
	am.NTLMResponse.OffSet = 64 + Uint32LE(payloadBuf.Len())
	am.NTLMResponse.WriteBytesToBuffer(buf, payloadBuf)
	am.Domain.OffSet = 64 + Uint32LE(payloadBuf.Len())
	am.Domain.WriteBytesToBuffer(buf, payloadBuf)
	am.User.OffSet = 64 + Uint32LE(payloadBuf.Len())
	am.User.WriteBytesToBuffer(buf, payloadBuf)
	am.WorkStation.OffSet = 64 + Uint32LE(payloadBuf.Len())
	am.WorkStation.WriteBytesToBuffer(buf, payloadBuf)
	am.SessionKey.OffSet = 64 + Uint32LE(payloadBuf.Len())
	am.SessionKey.WriteBytesToBuffer(buf, payloadBuf)
	am.Flag.WriteBytesToBuffer(buf)
	buf.Write(payloadBuf.Bytes())
}
