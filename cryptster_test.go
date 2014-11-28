package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/Triztian/cryptster/digest"
)

func TestSHA(t *testing.T) {
	message := "The quick brown fox jumps over the lazy dog"
	hexString := "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
	dmsg := make([]byte, bytes.MinRead)

	sha := digest.SHA1{}
	reader := strings.NewReader(message)

	read, err := reader.Read(dmsg)
	if read > 0 && err == nil {
		computedHex := hex.EncodeToString(sha.Digest(dmsg))
		if computedHex != hexString {
			t.Error("Incorrect digest, should be \"" + hexString + "\" but was \"" + computedHex)
		}

		read, err = reader.Read(dmsg)
	} else {
	}
}
