package goHttpDigestClient

import (
	"crypto/md5"
	"fmt"
)

func toMd5(s string) string {
	sByte := []byte(s)
	return fmt.Sprintf("%x", md5.Sum(sByte))
}
