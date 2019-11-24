package bf

import (
	"bytes"
	"context"
	"encoding/pem"
	"io/ioutil"
	"strings"
	"testing"
	"time"
)

func TestFindPassphrase(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	keyFile, err := ioutil.ReadFile("./testdata/private_key.pem")
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(keyFile)

	cases := []struct {
		name          string
		wordlist      []string
		expPassphrase string
	}{
		{
			name: "returns a valid passphrase from the list",
			wordlist: []string{
				"some",
				"stupid",
				"passwords",
				"for",
				"the",
				"key",
				"brute",
				"force",
				"test",
				"and",
				"this",
			},
			expPassphrase: "test",
		},
		{
			name: "returns empty passphrase if nothing matches",
			wordlist: []string{
				"nothing",
				"to",
				"see",
				"here",
			},
		},
		{
			name: "returns empty passphrase if wordlist is empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			passwords := strings.Join(tc.wordlist, "\n")
			wordlist := bytes.NewBuffer([]byte(passwords))

			out := FindPassphrase(ctx, block, wordlist, 8, false)

			passphrase := <-out

			if string(passphrase) != tc.expPassphrase {
				t.Fail()
			}
		})
	}
}
