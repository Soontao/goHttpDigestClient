package goHttpDigestClient

import "fmt"

const (
	Https string = "https"
	Http  string = "http"
)

type ClientOption struct {
	schema   string
	domain   string
	authpath string
	username string
	password string
}

func NewClientOption(schema string, domain string, authpath string, username string, password string) *ClientOption {
	return &ClientOption{schema: schema, domain: domain, authpath: authpath, username: username, password: password}
}

func (co *ClientOption) GetUrlPrefix() string {
	return fmt.Sprintf("%s://%s", co.schema, co.domain)
}

func (co *ClientOption) GetAuthUrl() string {
	return fmt.Sprintf("%s%s", co.GetUrlPrefix(), co.authpath)
}
