package main

import (
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"crypto/rand"
	"crypto/sha256"

	"github.com/github/certstore"
)

func main() {
	// sig, err := signWithMyIdentity("Мухалов Сергей Юрьевич (4031382)", "hello, world!")
	// if err != nil {
	// 	panic(err)
	// }

	//fmt.Println(hex.EncodeToString(sig))

	serialNumber := "7108e0ca0001000083ea"
	identity, err := findIdentity(serialNumber)
	if err != nil {
		log.Fatal(err)
	}

	// cert, err := identity.Certificate()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// fmt.Println(cert.Subject.CommonName)
	// fmt.Println("OK")
	signer, err := identity.Signer()
	if err != nil {
		log.Fatal(err)
	}

	// Digest and sign our message.
	digest := sha256.Sum256([]byte("Вася Пупкин"))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(hex.EncodeToString(signature))
}

func signWithMyIdentity(cn, msg string) ([]byte, error) {
	// Open the certificate store for use. This must be Close()'ed once you're
	// finished with the store and any identities it contains.
	store, err := certstore.Open()
	if err != nil {
		return nil, err
	}
	defer store.Close()

	// Get an Identity slice, containing every identity in the store. Each of
	// these must be Close()'ed when you're done with them.
	idents, err := store.Identities()
	if err != nil {
		return nil, err
	}

	// Iterate through the identities, looking for the one we want.
	var me certstore.Identity
	for _, ident := range idents {
		defer ident.Close()

		crt, errr := ident.Certificate()
		if errr != nil {
			return nil, errr
		}

		if crt.Subject.CommonName == cn {
			me = ident
			//7108e0ca0001000083ea
			s := fmt.Sprintf("%x", crt.SerialNumber)
			fmt.Printf("%s\n", s)
		}

		//fmt.Println(crt.Subject.CommonName)
	}

	if me == nil {
		return nil, errors.New("Couldn't find my identity")
	}

	// Get a crypto.Signer for the identity.
	signer, err := me.Signer()
	if err != nil {
		return nil, err
	}

	// Digest and sign our message.
	digest := sha256.Sum256([]byte(msg))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func findIdentity(serialNumber string) (certstore.Identity, error) {
	store, err := certstore.Open()
	if err != nil {
		return nil, err
	}
	defer store.Close()

	identities, err := store.Identities()
	if err != nil {
		return nil, err
	}

	//var me certstore.Identity
	for _, identity := range identities {
		//defer identity.Close()

		crt, err := identity.Certificate()
		if err != nil {
			defer identity.Close()
			return nil, err
		}

		if fmt.Sprintf("%x", crt.SerialNumber) == serialNumber {
			me := identity
			return me, nil
		}

		defer identity.Close()
	}

	return nil, fmt.Errorf("Не найден сертификат SerailNumber = %s", serialNumber)
}
