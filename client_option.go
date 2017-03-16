package goHttpDigestClient

const (
	KEY_HTTPS string = "https"
	KEY_HTTP  string = "http"
)

type ClientOption struct {
	username string
	password string
}
