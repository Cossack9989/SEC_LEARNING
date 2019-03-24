package main

import (
	"encoding/base64"
	"fmt"
)

const (
	base64Table = "ABCyVPGHTJKLMNOFQRSIUEWDYZgbc8sfah1jklmnopqret5v0xX9wi234u67dz+/"
)

var coder = base64.NewEncoding(base64Table)

func base64Encode(src []byte) string {
	return coder.EncodeToString(src)
}
func main() {
	dec := "\x15\x55\xd3\x0f\x38\xb0\xdb\xca\xec\x83\xc0\xf9"
	fmt.Println([]byte(dec))
	plain := base64Encode([]byte(dec))
	fmt.Println(plain)
}
