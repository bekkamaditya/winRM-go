package ntlm

import (
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

func utf8ToUtf16(s string) []byte {
	uint16s := utf16.Encode([]rune(s))
	var ret = make([]byte, 2*len(uint16s))
	//fmt.Println("uint16s", uint16s)
	for i := range uint16s {
		binary.LittleEndian.PutUint16(ret[2*i:2*i+2], uint16s[i])
	}
	//fmt.Println("ret", ret)
	return ret
}

func utf16toString(b []byte) (string, error) {
	if len(b)&1 != 0 {
		return "", MalformedBytesError
	}
	return utf16BytesToString(b, binary.LittleEndian), nil
}
func utf16BytesToString(b []byte, o binary.ByteOrder) string {
	utf := make([]uint16, (len(b)+(2-1))/2)
	for i := 0; i+(2-1) < len(b); i += 2 {
		utf[i/2] = o.Uint16(b[i:])
	}
	if len(b)/2 < len(utf) {
		utf[len(utf)-1] = utf8.RuneError
	}
	return string(utf16.Decode(utf))
}
