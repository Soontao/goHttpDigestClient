package goHttpDigestClient

import (
	"net/http"
)

type Client struct {
	is_init            bool
	username, password string
	option             ClientOption
	http.Client
}

func NewClient() *Client {
	return &Client{}
}

func GetWwwAuthFromHeader(h *http.Header) WwwAuthorization {
	return NewWwwAuthHeader(h.Get("WWW-Authenticate"))
}

func (c *Client) Do(req *http.Request, opt *ClientOption) (*http.Response, error) {
	res, err := c.Client.Do(req)
	if res.StatusCode == http.StatusUnauthorized {
		www_auth := GetWwwAuthFromHeader(&res.Header)
		www_auth.ComputeResponse(req.Method, req.URL.RequestURI(), "", opt.username, opt.password)
		authorization := www_auth.ToAuthorizationStr()
		req.Header.Set(KEY_AUTHORIZATION, authorization)
		return c.Client.Do(req)
	} else {
		return res, err
	}
}

var DefaultClient = &Client{}
