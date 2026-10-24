package crypt_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/soroushj/crypt"
)

func Example() {
	password := []byte("correct horse battery staple")

	var encrypted bytes.Buffer
	w, err := crypt.NewWriter(&encrypted, password, crypt.LowMemoryParams)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := io.WriteString(w, "Hello, world!\n"); err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	r, err := crypt.NewReader(&encrypted, password)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := io.Copy(os.Stdout, r); err != nil {
		log.Fatal(err)
	}
	// Output: Hello, world!
}

func ExampleNewReader_wrongPassword() {
	var encrypted bytes.Buffer
	w, err := crypt.NewWriter(&encrypted, []byte("correct horse battery staple"), crypt.LowMemoryParams)
	if err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	r, err := crypt.NewReader(&encrypted, []byte("Tr0ub4dor&3"))
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(io.Discard, r)
	fmt.Println(errors.Is(err, crypt.ErrAuthentication))
	// Output: true
}
