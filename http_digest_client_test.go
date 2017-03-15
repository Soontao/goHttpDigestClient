package goHttpDigestClient

import "testing"
import "github.com/stretchr/testify/assert"
import "net/http"

const (
	testWwwAuthHeader = `Digest realm="Users", nonce="EIQrqdZGXLGKROqDCs4YoRDtnXzZTthi", qop="auth"`
)

func TestNewClientOption(t *testing.T) {
	co := NewClientOption(Http, "127.0.0.1", "/auth", "u", "p")
	assert.Equal(t, "http://127.0.0.1", co.GetUrlPrefix(), "get url prefix error")
	assert.Equal(t, "http://127.0.0.1/auth", co.GetAuthUrl(), "get auth url error")
	t.Skip("NewClientOPtion Pass")
}

func TestGetAuthInfoFromHeader(t *testing.T) {
	h := http.Header{}
	h.Set("WWW-Authenticate", `Digest realm="Users", nonce="EIQrqdZGXLGKROqDCs4YoRDtnXzZTthi", qop="auth"`)
	authOption := GetAuthInfoFromHeader(&h)
	assert.Equal(t, "Digest", authOption.GetAuthItem(DIGESTAUTHTYPE), "auth type")
	assert.Equal(t, "Users", authOption.GetAuthItem(DIGESTREALM), "auth realm")
	assert.Equal(t, "EIQrqdZGXLGKROqDCs4YoRDtnXzZTthi", authOption.GetAuthItem(DIGESTSERVERNONCE), "auth server nonce")
	assert.Equal(t, "auth", authOption.GetAuthItem(DIGESTQOP), "auth qop")
	t.Skip("GetAuthInfoFromHeader can get all info from header['www-authenticate']")
}

func TestIsDigestAuth(t *testing.T) {
	h := http.Header{}
	h.Set("WWW-Authenticate", `Digest realm="Users", nonce="EIQrqdZGXLGKROqDCs4YoRDtnXzZTthi", qop="auth"`)
	authOption := GetAuthInfoFromHeader(&h)
	assert.True(t, authOption.IsDigestAuth(), "auth type is Digest")
	t.Skip("IsDigestAuth pass")
}

func TestNewDigestAuthInfo(t *testing.T) {
	dai := NewDigestAuthInfo(`Digest realm="Users", nonce="EIQrqdZGXLGKROqDCs4YoRDtnXzZTthi", qop="auth"`)
	assert.Equal(t, "Digest", dai.GetAuthItem(DIGESTAUTHTYPE), "auth type")
	assert.Equal(t, "Users", dai.GetAuthItem(DIGESTREALM), "auth realm")
	assert.Equal(t, "EIQrqdZGXLGKROqDCs4YoRDtnXzZTthi", dai.GetAuthItem(DIGESTSERVERNONCE), "auth server nonce")
	assert.Equal(t, "auth", dai.GetAuthItem(DIGESTQOP), "auth qop")
	t.Skip("create new DigestAuthInfo pass")
}

func TestToWwwHeaderStr(t *testing.T) {
	dai := NewDigestAuthInfo(testWwwAuthHeader)
	assert.Equal(t, testWwwAuthHeader, dai.ToWwwHeaderStr(), "should be equal")
	t.Skip()
}

func TestToMd5(t *testing.T) {
	source := "u:Users:p"
	target := "e098ce4fd4536daadc81bc661181cb19"
	assert.Equal(t, target, toMd5(source), "md5 check")
	t.Skip()
}
