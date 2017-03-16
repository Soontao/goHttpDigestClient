package goHttpDigestClient

import (
	"fmt"
	"strings"
)

const (
	KEY_DIGEST        = "Digest"
	KEY_AUTH_SCHEMA   = "auth_schema"
	KEY_QOP           = "qop"
	KEY_NONCE         = "nonce"
	KEY_CNONCE        = "cnonce"
	KEY_USERNAME      = "username"
	KEY_NONCE_COUNT   = "nc"
	KEY_OPAQUE        = "opaque"
	KEY_RESPONSE      = "response"
	KEY_REALM         = "realm"
	KEY_AUTHORIZATION = "Authorization"
	KEY_URI           = "uri"
)

type WwwAuthorization map[string]string

func NewWwwAuthHeader(wwwAuthHeader string) WwwAuthorization {
	r := WwwAuthorization{}
	wwwAuthArr := strings.Split(strings.Replace(wwwAuthHeader, ",", "", -1), " ")
	wwwAuthArrLen := len(wwwAuthArr)
	if wwwAuthArrLen > 1 {
		r[KEY_AUTH_SCHEMA] = wwwAuthArr[0]
		for i := 1; i < wwwAuthArrLen; i++ {
			itemArr := strings.Split(wwwAuthArr[i], "=")
			r.SetAuthItem(itemArr[0], itemArr[1])
		}
	}
	return r
}

func (info WwwAuthorization) IsDigestAuth() bool {
	return info[KEY_AUTH_SCHEMA] == KEY_DIGEST
}

func (info WwwAuthorization) SetAuthItem(itemKey string, itemValue string) {
	info[itemKey] = itemValue
}

func (info WwwAuthorization) GetAuthItem(itemKey string) string {
	return strings.Replace(info[itemKey], `"`, "", -1)
}

func (info WwwAuthorization) GetAuthItemOrigin(itemKey string) string {
	return info[itemKey]
}

func (info WwwAuthorization) ToAuthorizationStr() string {
	authType := KEY_DIGEST
	authItemStr := ""
	// how to specify the sequence
	for k, _ := range info {
		if k != KEY_AUTH_SCHEMA {
			authItemStr += fmt.Sprintf(", %s=\"%s\"", k, info.GetAuthItem(k))
		}
	}
	return authType + strings.Replace(authItemStr, ",", "", 1)
}

func (h WwwAuthorization) ComputeResponse(method, uri, entity, username, password string) WwwAuthorization {
	qop := h.GetAuthItem(KEY_QOP)
	realm := h.GetAuthItem(KEY_REALM)
	nonce := h.GetAuthItem(KEY_NONCE)
	nonceCount := h.GetAuthItem(KEY_NONCE_COUNT)
	cNonce := h.GetAuthItem(KEY_CNONCE)
	response, cNonce, nonceCount := computeResponse(qop, realm, nonce, nonceCount, cNonce, method, uri, entity, username, password)
	h.SetAuthItem(KEY_USERNAME, `"`+username+`"`)
	h.SetAuthItem(KEY_URI, uri)
	h.SetAuthItem(KEY_CNONCE, cNonce)
	h.SetAuthItem(KEY_NONCE_COUNT, nonceCount)
	h.SetAuthItem(KEY_RESPONSE, response)
	return h
}
