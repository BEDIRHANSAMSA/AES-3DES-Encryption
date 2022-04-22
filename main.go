package main

import (
	"fmt"
	"github.com/BEDIRHANSAMSA/AES-3DES-Encryption/aes"
	"github.com/BEDIRHANSAMSA/AES-3DES-Encryption/tripleDes"
)

func main() {
	aesEncrypt()
	tripleDesEncrypt()
}

func aesEncrypt() {
	fmt.Println("AES SIFRELEME BASLIYOR.")
	plainText := "Bu metin sifrelenecektir."
	secret := "testtesttesttest"

	fmt.Println("Plain Text:", plainText)

	encText := aes.Encrypt(plainText, secret)
	fmt.Println("Encrypted Text:", encText)

	decText := aes.Decrypt(encText, secret)
	fmt.Println("Decrypted Text:", decText)

	fmt.Println("AES SIFRELEME BITTI.\n\n")
}

func tripleDesEncrypt() {
	fmt.Println("3DES SIFRELEME BASLIYOR.")
	plainText := "Bu metin sifrelenecektir."
	secret := "123456781234567812345678"

	fmt.Println("Plain Text:", plainText)

	encText := tripleDes.Encrypt(plainText, secret)
	fmt.Println("Encrypted Text:", encText)

	decText := tripleDes.Decrypt(encText, secret)
	fmt.Println("Decrypted Text:", decText)

	fmt.Println("3DES SIFRELEME BITTI.\n\n")
}
