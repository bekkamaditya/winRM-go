package ntlm

import (
//	"fmt"
)

type ChallengeMessage struct {
	Signature       string
	Type            Uint32LE
	TargetName      SecurityBuffer
	Flag            NegotiateFlag
	ServerChallenge []byte
	Reserved        Uint64LE
	TargetInfo      SecurityBuffer
	fullPayload     []byte
}

func ParseChallengeMessage(p []byte) (ChallengeMessage, error) {
	var cm ChallengeMessage
	var ci int
	var err error
	if len(p) < 48 {
		return cm, MalformedBytesError
	}
	cm.Signature = string(p[ci : ci+8])
	if cm.Signature != NTLMSig {
		return cm, MalformedBytesError
	}
	//fmt.Println(cm.Signature)
	ci += 8
	if len(p) < ci+4 {
		return cm, MalformedBytesError
	}
	cm.Type, err = ParseUint32LE(p[ci : ci+4])
	if err != nil {
		return cm, err
	}
	//fmt.Println(cm.Type)
	ci += 4
	if cm.Type != 2 {
		return cm, MalformedBytesError
	}
	if len(p) < ci+8 {
		return cm, MalformedBytesError
	}
	cm.TargetName, err = ParseSecurityBuffer(p[ci : ci+8])
	if err != nil {
		return cm, MalformedBytesError
	}
	ci += 8
	targetNameOffset := int(cm.TargetName.OffSet)
	targetNameEnd := int(cm.TargetName.OffSet + Uint32LE(cm.TargetName.Len))
	if len(p) < targetNameOffset || len(p) < targetNameEnd {
		return cm, err
	}
	cm.TargetName.Value = p[targetNameOffset:targetNameEnd]
	if len(p) < ci+4 {
		return cm, MalformedBytesError
	}
	cm.Flag, err = ParseNegotiateFlag(p[ci : ci+4])
	if err != nil {
		return cm, err
	}
	ci += 4
	if len(p) < ci+8 {
		return cm, MalformedBytesError
	}
	cm.ServerChallenge = p[ci : ci+8]
	if len(p) < ci+8 {
		return cm, MalformedBytesError
	}
	ci += 8
	cm.Reserved, _ = ParseUint64LE(p[ci : ci+8])
	if len(p) < ci+8 {
		return cm, MalformedBytesError
	}
	ci += 8
	cm.TargetInfo, err = ParseSecurityBuffer(p[ci : ci+8])
	if err != nil {
		return cm, err
	}
	ci += 8
	targetInfoOffset := int(cm.TargetInfo.OffSet)
	targetInfoLen := int(cm.TargetInfo.OffSet + Uint32LE(cm.TargetInfo.Len))
	if len(p) < targetInfoOffset || len(p) < targetInfoLen {
		return cm, MalformedBytesError
	}
	cm.TargetInfo.Value = p[targetInfoOffset:targetInfoLen]
	cm.fullPayload = p
	return cm, nil
}
