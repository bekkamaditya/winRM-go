package ntlm

import (
	"bytes"
	"encoding/base64"
	"os"

	"golang.org/x/crypto/md4"
)

type State uint16

const (
	Initial     State = 0
	Negotiating State = 1 << iota
	Negotiated
	ChallengeReceived
	Authenticated
)

const (
	ClientToServerSigning = "session key to client-to-server signing key magic constant\000"
	ServerToClientSigning = "session key to server-to-client signing key magic constant\000"
	ClientToServerSealing = "session key to client-to-server sealing key magic constant\000"
	ServerToClientSealing = "session key to server-to-client sealing key magic constant\000"
)

type Session struct {
	target              string
	username            string
	password            string
	domain              string
	State               State
	serverChallenge     []byte
	clientChallenge     []byte
	exportedSessionKey  []byte
	encryptedSessionKey []byte
	sessionBaseKey      []byte
	keyExchangeKey      []byte
	clientSigningKey    []byte
	clientSealingKey    []byte
	serverSigningKey    []byte
	serverSealiingKey   []byte
	timestamp           []byte
	wsName              string
	nmBytes             []byte
	cmBytes             []byte
	amBytes             []byte
	flag                NegotiateFlag
}

func NewSession(username, domain, password, target string) *Session {
	s := &Session{
		target:   target,
		username: username,
		domain:   domain,
		password: password,
		flag: NegotiateUnicode |
			NegotiateOEM |
			NegotiateSign |
			NegotiateSeal |
			NegotiateRequestTarget |
			NegotiateNTLM |
			NegotiateAlwaysSign |
			NegotiateNTLMV2Key |
			NegotiateKey128 |
			NegotiateKeyExchange |
			NegotiateKey56,
	}
	return s
}

func (s *Session) Seal([]byte) ([]byte, error) {
	return nil, nil
}

func (s *Session) Sign([]byte) ([]byte, error) {
	return nil, nil
}

func (s *Session) GetState() State {
	return s.State
}

func (s *Session) Authenticate(cm string) (string, error) {
	s.State = ChallengeReceived
	cmb64 := cm
	cmbs, err := base64.StdEncoding.DecodeString(cmb64)
	if err != nil {
		return "", err
	}
	//fmt.Println("err is ", err)
	am, err := s.ProcessChallengeMessage(cmbs)
	if err != nil {
		return "", err
	}
	//fmt.Println(am)
	amBytes := Serialize(am)
	s.amBytes = amBytes
	s.State = Authenticated
	return SerializeBytesToBase64(amBytes), nil
}

func (s *Session) Negotiate() (string, error) {
	s.State = Negotiated
	nm := NewNegotiateMessage(s.domain, s.GetWorkStationName())
	nm.Flag = s.flag
	nmBytes := Serialize(nm)
	s.nmBytes = nmBytes
	nmB64 := SerializeBytesToBase64(nmBytes)
	return nmB64, nil
}

func (s *Session) getLMNTLMV2Responses(cm ChallengeMessage) ([]byte, []byte) {
	bb := NewBlobWithChallenge(s.clientChallenge, s.GetTargetInfo(cm))
	bbBytes := Serialize(bb)

	ntlmV2Hash := NTLMV2Hash(s.username, s.password, s.domain, cm.Flag)
	ntProof := NTProof(ntlmV2Hash, s.serverChallenge, bbBytes)
	ntlmV2Resp := NtlmV2Response(ntProof, bbBytes)
	lmSig := HMACMD5(ntlmV2Hash, concat(s.serverChallenge, s.clientChallenge))
	lmV2Resp := concat(lmSig, s.clientChallenge)
	s.sessionBaseKey = HMACMD5(ntlmV2Hash, ntProof)
	return ntlmV2Resp, lmV2Resp
}

func (s *Session) ProcessChallengeMessage(ps []byte) (AuthenticateMessage, error) {
	var am AuthenticateMessage
	cm, err := ParseChallengeMessage(ps)
	if err != nil {
		return am, nil
	}
	//fmt.Println("cm is ", cm)
	//fmt.Println(err)
	s.clientChallenge = getRandom(8)
	s.serverChallenge = cm.ServerChallenge
	var amSessionKey []byte
	ntlmV2Resp, lmV2Resp := s.getLMNTLMV2Responses(cm)
	if cm.Flag&NegotiateKeyExchange == NegotiateKeyExchange {
		s.exportedSessionKey = getRandom(16)
		amSessionKey, _ = rc4Encrypt(s.sessionBaseKey, s.exportedSessionKey)
	} else {
		s.exportedSessionKey = s.sessionBaseKey
	}
	am = NewAuthenticateMessage()
	am.LMResponse.Value = lmV2Resp
	am.NTLMResponse.Value = ntlmV2Resp
	am.Flag = s.flag & cm.Flag
	am.User.Value = getStrBytes(s.username, am.Flag)
	am.Domain.Value = getStrBytes(s.domain, am.Flag)
	am.WorkStation.Value = getStrBytes(s.GetWorkStationName(), am.Flag)
	am.SessionKey.Value = amSessionKey
	return am, nil
}

func (s *Session) GetTargetInfo(cm ChallengeMessage) []byte {
	return cm.TargetInfo.Value
}

func computeMD4Hash(b []byte) []byte {
	md4h := md4.New()
	md4h.Write(b)
	return md4h.Sum(nil)
}

func writeZero(buf *bytes.Buffer, n int) {
	for i := 0; i < n; i++ {
		buf.WriteByte(0x00)
	}
}

func (s *Session) GetWorkStationName() string {
	if s.wsName == "" {
		h, err := os.Hostname()
		if err != nil {
			h = "calm.machine"
		}
		s.wsName = h
	}
	return s.wsName
}
