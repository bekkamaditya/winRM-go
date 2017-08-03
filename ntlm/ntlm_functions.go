package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/md4"
)

const TimeOffset = Uint64LE(116444736000000000)

func getStrBytes(str string, flag NegotiateFlag) []byte {
	if (flag&NegotiateOEM == 0) || (flag&NegotiateUnicode == NegotiateUnicode) {
		return utf8ToUtf16(str)
	}
	return []byte(str)
}

func NTLMHash(password string, flag NegotiateFlag) []byte {
	md4h := md4.New()
	md4h.Write(getStrBytes(password, flag))
	return md4h.Sum(nil)
}

func HMACMD5(key, data []byte) []byte {
	hm := hmac.New(md5.New, key)
	hm.Write(data)
	return hm.Sum(nil)
}

func NTLMV2Hash(username, password, domain string, flag NegotiateFlag) []byte {
	userDom := fmt.Sprintf("%s%s", strings.ToUpper(username), domain)
	userDomBytes := getStrBytes(userDom, flag)
	return HMACMD5(NTLMHash(password, flag), userDomBytes)
}

func TimeStamp() Uint64LE {
	now := time.Now().UTC()
	return (Uint64LE(now.Unix()) + TimeOffset) * 10000000
}

func NewBlobWithChallenge(clientChallenge []byte, targetInfo []byte) Blob {
	var bb = NewBlob()
	bb.Challenge = clientChallenge
	bb.TargetInfo = targetInfo
	bb.Timestamp = TimeStamp()
	return bb
}

func concat(a []byte, b []byte) []byte {
	var buf = &bytes.Buffer{}
	buf.Grow(len(a) + len(b))
	buf.Write(a)
	buf.Write(b)
	return buf.Bytes()
}

func NTProof(ntlmV2Hash []byte, serverChallenge []byte, blob []byte) []byte {
	return HMACMD5(ntlmV2Hash, concat(serverChallenge, blob))
}

func NtlmV2Response(ntProofStr []byte, blob []byte) []byte {
	return concat(ntProofStr, blob)
}

func getRandom(bs int) []byte {
	var ret = make([]byte, bs)
	rand.Read(ret)
	return ret
}
