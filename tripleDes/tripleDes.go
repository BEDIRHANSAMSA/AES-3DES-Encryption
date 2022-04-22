package tripleDes

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
)

func Encrypt(plainText string, keyText string) string {
	// Metni byte dizisine donsturduk.
	plainByte := []byte(plainText)

	// Key'i byte dizisine donusturduk.
	key := []byte(keyText)

	block, err := des.NewTripleDESCipher(key)
	checkError(err)

	// Key'den des.BlockSize kadar olan kismini IV'ye atadik.
	iv := []byte(keyText[:des.BlockSize])

	origData := PKCS5Padding(plainByte, block.BlockSize())
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(origData))
	mode.CryptBlocks(encrypted, origData)
	return hex.EncodeToString(encrypted)
}

func Decrypt(cipherText string, keyText string) string {
	// Sifrelenmis array hex formatinda oldugu icin tekrardan byte dizisine donusturduk.
	cipherByte, _ := hex.DecodeString(cipherText)

	// Key'i byte dizisine donusturduk.
	key := []byte(keyText)

	block, err := des.NewTripleDESCipher(key)
	checkError(err)

	// Key'den des.BlockSize kadar olan kismini IV'ye atadik.
	iv := []byte(keyText[:des.BlockSize])

	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(cipherByte))
	decrypter.CryptBlocks(decrypted, cipherByte)
	decrypted = PKCS5UnPadding(decrypted)
	return string(decrypted)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}
