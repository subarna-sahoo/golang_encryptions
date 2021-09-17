package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
)

func main() {

	text := "subu123"
	key := "abcdefgh12345678"

	fmt.Println("\nmessage: ", text)

	enc_res := encrypt(text, key)
	fmt.Println("enc_res: ", enc_res)

	dec_res := decrypt(enc_res, key)
	fmt.Println("dec_res: ", dec_res)
}

func encrypt(text, key string) string {
	msg := []byte(text)
	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
	}
	resp := gcm.Seal(nonce, nonce, msg, nil)

	err = ioutil.WriteFile("./myfile.data", gcm.Seal(nonce, nonce, msg, nil), 0777)
	if err != nil {
		fmt.Println(err)
	}

	return base64.StdEncoding.EncodeToString(resp)
}

func decrypt(enc_text, key string) string {

	ciphertext, err := ioutil.ReadFile("./myfile.data")

	if err != nil {
		fmt.Println(err)
	}

	c, err := aes.NewCipher([]byte(key))
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Println(err)
	}

	return string(plaintext)
}
