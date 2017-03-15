package goHttpDigestClient

import (
	"fmt"
	"net/http"
	"strings"
)

const (
	DIGEST            = "Digest"
	DIGESTAUTHTYPE    = "authtype" // name need to be modify
	DIGESTQOP         = "qop"
	DIGESTSERVERNONCE = "nonce"
	DIGESTCLIENTNONCE = "cnonce"
	DIGESTNONCECOUNT  = "nc"
	DIGESTUSERNAME    = "username"
	DIGESTOPAQUE      = "opaque"
	DIGESTRESPONSE    = "response"
	DIGESTREALM       = "realm"
)

type DigestAuthInfo map[string]string

func NewDigestAuthInfo(wwwAuthHeader string) DigestAuthInfo {
	r := DigestAuthInfo{}
	wwwAuthArr := strings.Split(strings.Replace(wwwAuthHeader, ",", "", -1), " ")
	wwwAuthArrLen := len(wwwAuthArr)
	if wwwAuthArrLen > 1 {
		r[DIGESTAUTHTYPE] = wwwAuthArr[0]
		for i := 1; i < wwwAuthArrLen; i++ {
			itemArr := strings.Split(wwwAuthArr[i], "=")
			r.SetAuthItem(itemArr[0], itemArr[1])
		}
	}
	return r
}

func (info DigestAuthInfo) IsDigestAuth() bool {
	return info[DIGESTAUTHTYPE] == DIGEST
}

func (info DigestAuthInfo) SetAuthItem(itemKey string, itemValue string) {
	info[itemKey] = itemValue
}

func (info DigestAuthInfo) GetAuthItem(itemKey string) string {
	return strings.Replace(info[itemKey], `"`, "", -1)
}

func (info DigestAuthInfo) GetAuthItemOrigin(itemKey string) string {
	return info[itemKey]
}

func (info DigestAuthInfo) AddToHeader(h *http.Header) {

}

func (info DigestAuthInfo) ToWwwHeaderStr() string {
	authType := DIGEST
	authItemStr := ""
	// how to specify the sequence
	for k, v := range info {
		if k != DIGESTAUTHTYPE {
			authItemStr += fmt.Sprintf(", %s=%s", k, v)
		}
	}
	return authType + strings.Replace(authItemStr, ",", "", 1)
}
