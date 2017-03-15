package goHttpDigestClient

import (
	"net/http"
)

type Client struct {
	inited bool
	qop    string
	auth   string
}

func NewClient() *Client {
	return &Client{}
}

func GetAuthInfoFromHeader(h *http.Header) DigestAuthInfo {
	return NewDigestAuthInfo(h.Get("WWW-Authenticate"))
}

func computeAuthResponse(info DigestAuthInfo) string {
	r := ""
	if info.GetAuthItem(DIGESTQOP) != "" {

	}
	return r
}
