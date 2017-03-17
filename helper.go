package goHttpDigestClient

import (
	"fmt"
	"strings"
)

const (
	KEY_DIGEST           = "Digest"
	KEY_AUTH_SCHEMA      = "auth_schema"
	KEY_QOP              = "qop"
	KEY_NONCE            = "nonce"
	KEY_CNONCE           = "cnonce"
	KEY_USERNAME         = "username"
	KEY_NONCE_COUNT      = "nc"
	KEY_OPAQUE           = "opaque"
	KEY_RESPONSE         = "response"
	KEY_REALM            = "realm"
	KEY_AUTHORIZATION    = "Authorization"
	KEY_URI              = "uri"
	KEY_WWW_Authenticate = "WWW-Authenticate"
)

//The 401 (Unauthorized) response message is used by an origin server
//to challenge the authorization of a user agent.
//
// And the CHALLENGE will include informations about auth
type Challenge map[string]string

func NewChallenge(wwwAuthHeader string) Challenge {
	r := Challenge{}
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

func (info Challenge) IsDigestAuth() bool {
	return info[KEY_AUTH_SCHEMA] == KEY_DIGEST
}

func (info Challenge) SetAuthItem(itemKey string, itemValue string) {
	info[itemKey] = itemValue
}

func (info Challenge) GetAuthItemPure(itemKey string) string {
	return strings.Replace(info[itemKey], `"`, "", -1)
}

func (info Challenge) GetAuthItemFormat(itemKey string) string {
	r := info.GetAuthItemPure(itemKey)
	switch itemKey {
	case KEY_QOP, KEY_NONCE_COUNT:
		return r
	default:
		return fmt.Sprintf(`"%s"`, r)
	}
}

func (info Challenge) ToAuthorizationStr() string {
	authType := KEY_DIGEST
	authItemStr := ""
	// how to specify the sequence
	for k, _ := range info {
		if k != KEY_AUTH_SCHEMA {
			authItemStr += fmt.Sprintf(", %s=%s", k, info.GetAuthItemFormat(k))
		}
	}
	return authType + strings.Replace(authItemStr, ",", "", 1)
}

func (h Challenge) ComputeResponse(method, uri, entity, username, password string) Challenge {
	qop := h.GetAuthItemPure(KEY_QOP)
	realm := h.GetAuthItemPure(KEY_REALM)
	nonce := h.GetAuthItemPure(KEY_NONCE)
	nonceCount := h.GetAuthItemPure(KEY_NONCE_COUNT)
	cNonce := h.GetAuthItemPure(KEY_CNONCE)
	response, cNonce, nonceCount := computeResponse(qop, realm, nonce, nonceCount, cNonce, method, uri, entity, username, password)
	h.SetAuthItem(KEY_USERNAME, `"`+username+`"`)
	h.SetAuthItem(KEY_URI, uri)
	h.SetAuthItem(KEY_CNONCE, cNonce)
	h.SetAuthItem(KEY_NONCE_COUNT, nonceCount)
	h.SetAuthItem(KEY_RESPONSE, response)
	return h
}
