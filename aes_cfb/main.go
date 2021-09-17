package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {

	const secretKey string = "abcdefgh12345678"
	message := "subu123"
	fmt.Println("\nmessage : ", message)

	enc, err := Encrypt(message, secretKey)
	if err != nil {
		log.Fatal("error encrypting your message: ", err)
	}
	fmt.Println("encrypted : ", enc)

	// decrytp
	dec, err := Decrypt(enc, secretKey)
	if err != nil {
		log.Fatal("error decrypting your message: ", err)
	}
	fmt.Println("decrypted : ", dec)

}

var iv = []byte("abcdefgh12345678")

func encodBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func decodeBase64(s string) []byte {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return data
}

func Encrypt(text, secretKey string) (string, error) {
	var iv = []byte(secretKey)
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}
	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, iv)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)
	return encodBase64(cipherText), nil
}

func Decrypt(text, secretKey string) (string, error) {
	var iv = []byte(secretKey)
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		return "", err
	}
	cipherText := decodeBase64(text)
	cfb := cipher.NewCFBDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil

}
