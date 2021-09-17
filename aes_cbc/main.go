package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

func main() {

	message := "exampleplaintext"
	key := "6368616e676520746869732070617373"

	fmt.Println("\nMessage: ", message)

	enc_res := encryption(message, key)
	fmt.Println("Enc_res: ", enc_res)

	dec_res := decryption(enc_res, key)
	fmt.Println("Dec_res: ", dec_res)

}

func encryption(message, _key string) string {
	key, _ := hex.DecodeString(_key)
	plaintext := []byte(message)

	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	// fmt.Printf("%x\n", ciphertext)
	return hex.EncodeToString(ciphertext)
}

func decryption(enc_message, _key string) string {
	key, _ := hex.DecodeString(_key)
	ciphertext, _ := hex.DecodeString(enc_message)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	return string(ciphertext)
}
