package ntlm

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

var ErrHeadersNotFound = fmt.Errorf("NTLM Headers not found")
var ErrMalformedHeader = fmt.Errorf("Malformed NTLM Headers")

type Negotiator interface {
	Negotiate() (string, error)
}

type Authenticator interface {
	Authenticate(string) (string, error)
}

type Sealer interface {
	Seal([]byte) ([]byte, error)
}

type Signer interface {
	Sign([]byte) ([]byte, error)
}

type SignedSealedNegotiatingAuthenticator interface {
	GetState() State
	Negotiator
	Authenticator
	Signer
	Sealer
}

type Client struct {
	cl         *http.Client
	baseURL    string
	username   string
	domain     string
	target     string
	password   string
	port       uint16
	s          SignedSealedNegotiatingAuthenticator
	authHeader string
	sentAuth   bool
}

func NewClient(username, domain, password, target string, port uint16) *Client {
	protocol := "http"
	c := &Client{
		target:   target,
		username: username,
		domain:   domain,
		password: password,
		port:     port,
		baseURL:  fmt.Sprintf("%s://%s:%d/wsman", protocol, target, port),
		s:        NewSession(username, domain, password, target),
	}
	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}
	c.cl = &http.Client{
		Transport: tr,
	}
	return c
}

func (c *Client) getBaseRequest() *http.Request {
	req, _ := http.NewRequest("POST", c.baseURL, nil)
	req.Header["Content-Type"] = []string{"application/soap+xml;charset=UTF-8"}
	return req
}

func (c *Client) getNTLMMessageFromHeader(resp *http.Response) (string, error) {
	h := resp.Header["Www-Authenticate"]
	if len(h) == 0 {
		return "", ErrHeadersNotFound
	}
	hs := strings.Split(h[0], " ")
	if len(hs) < 2 {
		return "", ErrMalformedHeader
	}
	return hs[1], nil
}

func (c *Client) getAuthorizationHeader(token string) []string {
	return []string{fmt.Sprintf("Negotiate %s", token)}
}

func (c *Client) setAuthHeader(req *http.Request, token string) {
	req.Header["Authorization"] = c.getAuthorizationHeader(token)
}

func (c *Client) Authenticate() error {
	nm, _ := c.s.Negotiate()
	req := c.getBaseRequest()
	c.setAuthHeader(req, nm)
	resp, err := c.cl.Do(req)
	if err != nil {
		return err
	}
	cmB64, err := c.getNTLMMessageFromHeader(resp)
	if err != nil {
		return err
	}
	am, err := c.s.Authenticate(cmB64)
	if err != nil {
		return err
	}
	c.authHeader = am
	return nil
}
func (c *Client) SendMessage(bs []byte) error {
	if c.s.GetState() != Authenticated {
		err := c.Authenticate()
		if err != nil {
			return err
		}
	}
	req := c.getBaseRequest()
	if !c.sentAuth {
		c.setAuthHeader(req, c.authHeader)
	}
	resp, err := c.cl.Do(req)
	fmt.Println("resp.code %s", resp.StatusCode)
	fmt.Println(err)
	return nil
}
