package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"

	"github.com/pragmader/x509bf/bf"
)

func main() {
	var wordlist, key string
	var concurrency uint
	var verbose bool
	flag.StringVar(&wordlist, "l", "", "path to the wordlist to try, e.g. /usr/share/wordlists/rockyou.txt")
	flag.StringVar(&key, "k", "", "path to the encrypted PEM file")
	flag.UintVar(&concurrency, "c", uint(runtime.NumCPU()), "level of concurrency, number of cores is the default")
	flag.BoolVar(&verbose, "v", false, "verbose logging (slower)")
	flag.Parse()

	if wordlist == "" {
		fmt.Println("wordlist (-l) is not set")
		flag.Usage()
		os.Exit(1)
	}

	if key == "" {
		fmt.Println("key (-k) is not set")
		flag.Usage()
		os.Exit(1)
	}

	wordlistFile, err := os.Open(wordlist)
	if err != nil {
		log.Fatal(err)
	}
	defer wordlistFile.Close()

	keyFile, err := ioutil.ReadFile(key)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(keyFile)
	if !x509.IsEncryptedPEMBlock(block) {
		log.Fatal("this key is not encrypted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := bf.FindPassphrase(ctx, block, wordlistFile, concurrency, verbose)

	passphrase := <-out
	cancel()

	if len(passphrase) == 0 {
		os.Exit(1)
	}
	os.Stdout.Write(passphrase)
	os.Stdout.Write([]byte{'\n'})
}
