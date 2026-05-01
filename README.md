# goTOTP
HOTP and TOTP implimentation in go

---
## Motivation
On multiple ocasions, I have found myself looking for a simple implimentation of these algorythms - it is possible they exist, but I got tired of looking. So here is my implimentation of RFC 4226 HOTP and RFC 6238 TOTP.

## Usage
```go
package main

import (
	"fmt"

	"github.com/James-Seely-scln/goTOTP/v2"
)

func main() {
	TOTP, _ := goTOTP.TOTP("JBSWY3DPEHPK3PXP", 30)
	fmt.Println(TOTP)
}
```