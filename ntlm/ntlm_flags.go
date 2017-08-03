package ntlm

import (
	"bytes"
	//	"fmt"
)

type NegotiateFlag Uint32LE

func ParseNegotiateFlag(p []byte) (NegotiateFlag, error) {
	f, err := ParseUint32LE(p)
	return NegotiateFlag(f), err
}

const (
	NegotiateUnicode             NegotiateFlag = 0x00000001
	NegotiateOEM                 NegotiateFlag = 0x00000002
	NegotiateRequestTarget       NegotiateFlag = 0x00000004
	NegotiateMBZ9                NegotiateFlag = 0x00000008
	NegotiateSign                NegotiateFlag = 0x00000010
	NegotiateSeal                NegotiateFlag = 0x00000020
	NegotiateDatagram            NegotiateFlag = 0x00000040
	NegotiateNetware             NegotiateFlag = 0x00000100
	NegotiateNTLM                NegotiateFlag = 0x00000200
	NegotiateNTOnly              NegotiateFlag = 0x00000400
	NegotiateMBZ7                NegotiateFlag = 0x00000800
	NegotiateDomainSupplied      NegotiateFlag = 0x00001000
	NegotiateWorkstationSupplied NegotiateFlag = 0x00002000
	NegotiateLocalCall           NegotiateFlag = 0x00004000
	NegotiateAlwaysSign          NegotiateFlag = 0x00008000
	NegotiateTargetTypeDomain    NegotiateFlag = 0x00010000
	NegotiateNTLMV2Key           NegotiateFlag = 0x00080000
	NegotiateTargetInfo          NegotiateFlag = 0x00800000
	NegotiateKey128              NegotiateFlag = 0x20000000
	NegotiateKeyExchange         NegotiateFlag = 0x40000000
	NegotiateKey56               NegotiateFlag = 0x80000000
)

var allFlags = map[NegotiateFlag]string{
	NegotiateUnicode:             "NegotiateUnicode",
	NegotiateOEM:                 "NegotiateOEM",
	NegotiateRequestTarget:       "NegotiateRequestTarget",
	NegotiateMBZ9:                "NegotiateMBZ9",
	NegotiateSign:                "NegotiateSign",
	NegotiateSeal:                "NegotiateSeal",
	NegotiateDatagram:            "NegotiateDatagram",
	NegotiateNetware:             "NegotiateNetware",
	NegotiateNTLM:                "NegotiateNTLM",
	NegotiateNTOnly:              "NegotiateNTOnly",
	NegotiateMBZ7:                "NegotiateMBZ7",
	NegotiateDomainSupplied:      "NegotiateDomainSupplied",
	NegotiateWorkstationSupplied: "NegotiateWorkstationSupplied",
	NegotiateLocalCall:           "NegotiateLocalCall",
	NegotiateAlwaysSign:          "NegotiateAlwaysSign",
	NegotiateTargetTypeDomain:    "NegotiateTargetTypeDomain",
	NegotiateNTLMV2Key:           "NegotiateNTLMV2Key",
	NegotiateTargetInfo:          "NegotiateTargetInfo",
	NegotiateKey128:              "NegotiateKey128",
	NegotiateKeyExchange:         "NegotiateKeyExchange",
	NegotiateKey56:               "NegotiateKey56",
}

func (n NegotiateFlag) String() string {
	//fmt.Println("%b", uint32(n))
	var buf = &bytes.Buffer{}
	for flg := range allFlags {
		if n&flg == flg {
			//fmt.Println("%b", uint32(flg))
			buf.WriteString(allFlags[flg])
			buf.WriteString(" ")
		}
	}
	return buf.String()
}

func (n NegotiateFlag) WriteBytesToBuffer(buf *bytes.Buffer) {
	Uint32LE(n).WriteBytesToBuffer(buf)
}

var DefaultFlags = map[uint32]NegotiateFlag{
	0x01: NegotiateUnicode | NegotiateOEM | NegotiateRequestTarget | NegotiateNTLM | NegotiateAlwaysSign | NegotiateNTLMV2Key,
	0x02: NegotiateUnicode,
	0x03: NegotiateUnicode | NegotiateRequestTarget | NegotiateNTLM | NegotiateAlwaysSign | NegotiateNTLMV2Key,
}
