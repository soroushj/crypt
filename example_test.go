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
	password := []byte("correct horse battery staple")
	wrongPassword := []byte("Tr0ub4dor&3")

	var encrypted bytes.Buffer
	w, err := crypt.NewWriter(&encrypted, password, crypt.LowMemoryParams)
	if err != nil {
		log.Fatal(err)
	}
	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	r, err := crypt.NewReader(&encrypted, wrongPassword)
	if err != nil {
		log.Fatal(err)
	}
	_, err = io.Copy(io.Discard, r)
	fmt.Println(errors.Is(err, crypt.ErrAuthentication))
	// Output: true
}
