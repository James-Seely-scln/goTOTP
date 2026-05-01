package goTOTP

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"
)

// Used to generate a TOTP based on the key K and the number of seconds between generations X
func TOTP(K string, X int) (string, error) {
	return HOTP(K, int(time.Now().Unix())/X, 3)
}

// Used to generate a HOTP based on the key, counter and the type of hash (0 = SHA1 1 = SHA224, 2 = SHA256, 3 = SHA384, 4 = SHA512)
func HOTP(Key string, Counter int, hashType int) (string, error) {
	// Reformat K, C into the correct format
	C := make([]byte, 8)
	binary.BigEndian.PutUint64(C, uint64(Counter))
	K, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(Key)
	if err != nil {
		return "", errors.New("something went wrong decoding key")
	}

	// use the correct type of hash
	var h func() hash.Hash
	switch hashType {
	case 1:
		h = sha256.New224
	case 2:
		h = sha256.New
	case 3:
		h = sha512.New384
	case 4:
		h = sha512.New
	default:
		h = sha1.New
	}

	// Make the HMAC based on the key K and counter C
	HM := hmac.New(h, K)
	HM.Write(C)

	// Generate a 4-byte string (Dynamic Truncation)
	s := HM.Sum(nil)
	Offset := int(s[len(s)-1] & 0x0F)
	Sbits := binary.BigEndian.Uint32(s[Offset:Offset+4]) & 0x7FFFFFFF

	return fmt.Sprintf("%06d", Sbits%1000000), nil
}
