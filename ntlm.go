package winrm

import (
	ntlmssp "github.com/Azure/go-ntlmssp"
	"github.com/masterzen/winrm/soap"
	"winrm/ntlm"
	"net/http"
	"fmt"
	"strings"
)

// ClientNTLM provides a transport via NTLMv2
type ClientNTLM struct {
	clientRequest
	cli *ntlm.Client
}

// Transport creates the wrapped NTLM transport
func (c *ClientNTLM) Transport(endpoint *Endpoint) error {
	c.clientRequest.Transport(endpoint)
	c.clientRequest.transport = &ntlmssp.Negotiator{RoundTripper: c.clientRequest.transport}
	return nil
}

// Post make post to the winrm soap service (forwarded to clientRequest implementation)
func (c *ClientNTLM) Post(client *Client, request *soap.SoapMessage) (string, error) {
	httpClient := &http.Client{Transport: c.transport}
    req, err := http.NewRequest("POST", client.url, strings.NewReader(request.String()))
    if err != nil {
        return "", fmt.Errorf("impossible to create http request %s", err)
    }
	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
    req.SetBasicAuth(client.username, client.password)

	//NTLM authentication
	err = c.cli.Authenticate()
	if err!=nil {
		return "",err
	}
    resp, err := httpClient.Do(req)
    if err != nil {
        return "", fmt.Errorf("unknown error %s", err)
    }
	
    body, err := body(resp)
    if err != nil {
		fmt.Printf("http response error: %d - %s\n",resp.StatusCode,err.Error())
        return "", fmt.Errorf("http response error: %d - %s", resp.StatusCode, err.Error())
    }

    // if we have different 200 http status code
    // we must replace the error
    defer func() {
        if resp.StatusCode != 200 {
            body, err = "", fmt.Errorf("http error %d: %s", resp.StatusCode, body)
        }
    }()
	
    return body, err
}
