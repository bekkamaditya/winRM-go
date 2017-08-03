package ntlm

import (
	"bytes"
)

const (
	MsvAvEol             Uint16LE = 0x00
	MsvAvNbComputerName  Uint16LE = 0x01
	MsvAvNbDomainName    Uint16LE = 0x02
	MsvAvDNSComputerName Uint16LE = 0x03
	MsvAvDNSDomainName   Uint16LE = 0x04
	MsvAvDNSTreeName     Uint16LE = 0x05
	MsvAvFlags           Uint16LE = 0x06
	MsvAvTimestamp       Uint16LE = 0x07
	MsvAvSingleHost      Uint16LE = 0x08
	MsvAvTargetName      Uint16LE = 0x09
	MsvAvChannelBindings Uint16LE = 0x0A
)

var knownAvIds = map[Uint16LE]bool{
	MsvAvEol:             true,
	MsvAvNbComputerName:  true,
	MsvAvNbDomainName:    true,
	MsvAvDNSComputerName: true,
	MsvAvDNSDomainName:   true,
	MsvAvDNSTreeName:     true,
	MsvAvFlags:           true,
	MsvAvTimestamp:       true,
	MsvAvSingleHost:      true,
	MsvAvTargetName:      true,
	MsvAvChannelBindings: true,
}

type AvPair struct {
	AvID  Uint16LE
	AvLen Uint16LE
	AvVal []byte
}

func (avp AvPair) WriteBytesToBuffer(buf *bytes.Buffer) {
	avp.AvID.WriteBytesToBuffer(buf)
	avp.AvLen.WriteBytesToBuffer(buf)
	buf.Write(avp.AvVal)
}

type AvPairs []AvPair

func (avps AvPairs) WriteBytesToBuffer(buf *bytes.Buffer) {
	for i := range avps {
		avps[i].WriteBytesToBuffer(buf)
	}
}

func ParseAvps(p []byte) (AvPairs, error) {
	var ci int
	var res AvPairs
	lenp := len(p)
	for {
		if ci >= lenp {
			break
		}
		avp, err := ParseAvp(p[ci : ci+4])
		if err != nil {
			return nil, err
		}
		ci += 4
		avp.AvVal = p[ci : ci+int(avp.AvLen)]
		res = append(res, avp)
		ci += int(avp.AvLen)
	}
	return res, nil
}

func ParseAvp(p []byte) (AvPair, error) {
	var avp = AvPair{}
	var ci int
	var err error
	avp.AvID, err = ParseUint16LE(p[ci : ci+2])
	if err != nil {
		return avp, err
	}
	ci += 2
	avp.AvLen, err = ParseUint16LE(p[ci : ci+2])
	if err != nil {
		return avp, err
	}
	ci += 2
	return avp, nil
}
