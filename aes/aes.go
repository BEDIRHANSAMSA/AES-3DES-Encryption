package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

func Encrypt(plainText string, keyText string) string {
	// Metni byte dizisine donsturduk.
	plainByte := []byte(plainText)

	// Key'i byte dizisine donusturduk.
	key := []byte(keyText)

	// AES sifreleme algoritmasi olusturduk.
	block, err := aes.NewCipher(key)
	checkError(err)

	// 16 + metin boyutunda bos bir byte dizisi olsuturduk.
	// IV'yi bu dizi icinde tutmak icin.
	ciphertext := make([]byte, aes.BlockSize+len(plainByte))

	// Ciphertext'den aes.BlockSize kadar olan kismini IV'ye atadik.
	iv := ciphertext[:aes.BlockSize]

	// Rastgele IV'yi olusturduk.
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// Sifrelenmis stream olusturduk.
	stream := cipher.NewCFBEncrypter(block, iv)

	// Metni sifreliyoruz.
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plainByte)

	// Sifrelenmis byte arrayi hexadecimal string'e donusturuyoruz.
	return hex.EncodeToString(ciphertext)
}

func Decrypt(cipherText string, keyText string) string {
	// Sifrelenmis array hex formatinda oldugu icin tekrardan byte dizisine donusturduk.
	cipherByte, _ := hex.DecodeString(cipherText)

	// Key'i byte dizisine donusturduk.
	key := []byte(keyText)

	// AES sifreleme algoritmasi olusturduk.
	block, err := aes.NewCipher(key)
	checkError(err)

	// CipherText'den aes.BlockSize kadar olan kismini IV'ye atadik.
	iv := cipherByte[:aes.BlockSize]

	// CipherText'den aes.BlockSize kadar olan kismi IV'yi temizledik.
	cipherByte = cipherByte[aes.BlockSize:]

	// Sifre cozucu stream olusturduk.
	stream := cipher.NewCFBDecrypter(block, iv)

	// CipherText'i cozuyoruz.
	stream.XORKeyStream(cipherByte, cipherByte)

	// Cozulmus byte arrayi stringe donusturuyoruz.
	return string(cipherByte)
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}
