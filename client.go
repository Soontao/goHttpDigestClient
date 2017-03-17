package goHttpDigestClient

import (
	"io"
	"io/ioutil"
	"net/http"
)

// if option is set, get challenge at construct time
// if option not set, ever digest auth will send 2 request
type Client struct {
	is_init            bool
	username, password string
	option             ClientOption
	http.Client
}

type ClientOption struct {
	username string
	password string
}

var DefaultClient = &Client{}

func NewClient() *Client {
	// here need more attention
	return &Client{}
}

func GetChallengeFromHeader(h *http.Header) Challenge {
	return NewChallenge(h.Get(KEY_WWW_Authenticate))
}

func (c *Client) Do(req *http.Request, opt *ClientOption) (*http.Response, error) {
	res, err := c.Client.Do(req)
	if res.StatusCode == http.StatusUnauthorized {
		challenge := GetChallengeFromHeader(&res.Header)
		challenge.ComputeResponse(req.Method, req.URL.RequestURI(), getStrFromIO(req.Body), opt.username, opt.password)
		authorization := challenge.ToAuthorizationStr()
		req.Header.Set(KEY_AUTHORIZATION, authorization)
		return c.Client.Do(req)
	} else {
		return res, err
	}
}

// From ReadCloser to string
func getStrFromIO(r io.ReadCloser) string {
	if r == nil {
		return ""
	}
	if b, err := ioutil.ReadAll(r); err == nil {
		return string(b)
	} else {
		return ""
	}
}

// Default Client Do　Request
func Do(req *http.Request, opt *ClientOption) (*http.Response, error) {
	return DefaultClient.Do(req, opt)
}
