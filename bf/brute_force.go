package bf

import (
	"bufio"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"sync"
)

var (
	errIncorrect = errors.New("passphrase worked for neither PKCS1 nor PKCS8")
)

// FindPassphrase finds a passphrase from the new line-separated word list that matches
// the given encrypted key in PEM format. DEK header is required.
// `block` must be an enecrypted PEM block.
// `wordList` must be new line-separated.
// `concurrency` sets how many go routes perform the decryption at the same time.
// `verbose` turns on verbose logging.
func FindPassphrase(ctx context.Context, block *pem.Block, wordList io.Reader, concurrency uint, verbose bool) (out <-chan []byte) {
	outRW := make(chan []byte)
	// it's to control concurrency level via the pool pattern
	pool := make(chan bool, concurrency)

	go func() {
		defer close(outRW)

		var wg sync.WaitGroup

		scanner := bufio.NewScanner(wordList)

		for scanner.Scan() {
			// get the slot in the pool
			pool <- true

			line := scanner.Bytes()
			word := make([]byte, len(line))
			copy(word, line)

			select {

			case <-ctx.Done():
				return

			default:

				wg.Add(1)

				go func() {
					defer wg.Done()
					// release the slot in the pool
					defer func() { <-pool }()

					select {

					case <-ctx.Done():
						return

					default:
						err := tryWord(block, word, verbose)
						if err != nil {
							if verbose {
								log.Println(err)
							}
							return
						}
						outRW <- word
					}
				}()
			}
		}

		wg.Wait()
	}()

	return outRW
}

func tryWord(block *pem.Block, word []byte, verbose bool) error {
	if verbose {
		log.Printf("trying `%s`...", word)
	}

	der, err := x509.DecryptPEMBlock(block, word)
	if err != nil {
		return err
	}

	if verbose {
		log.Printf("found passphrase candidate `%s`", word)
		log.Println("trying to parse PKCS1")
	}

	_, err = x509.ParsePKCS1PrivateKey(der)
	if err == nil {
		if verbose {
			log.Printf("passphrase `%s` worked for PKCS1", word)
		}
		return nil
	}

	if verbose {
		log.Printf("passphrase `%s` didn't work for PKCS1", word)
		log.Println("trying to parse PKCS8...")
	}

	_, err = x509.ParsePKCS8PrivateKey(der)
	if err == nil {
		if verbose {
			log.Printf("passphrase `%s` worked for PKCS8", word)
		}
		return nil
	}

	if verbose {
		log.Printf("passphrase `%s` didn't work neither for PKCS1 nor PKCS8", word)
	}

	return errIncorrect
}
