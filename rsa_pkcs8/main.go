package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

func main() {

	msg := "subu123"
	fmt.Println("\nMessage: ", msg)

	encryptedData := EncryptData(msg)
	fmt.Println("EncryptedData: ", encryptedData)

	decryptedData, _ := DecryptData(encryptedData)
	fmt.Println("DecryptedData: ", decryptedData)

}

func EncryptData(msg string) string {

	msgByte := []byte(msg)
	// publicKeyData, _ := ioutil.ReadFile("public.pem")
	publicKeyData := `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4u0kIvdVjHojOeJ90Zy9e+sI2
Ov2011PikfETEjWTDUfTPRTcL3eTZSY9RIwWBgbbRLw5er4PK1xjuc7tLXo5f7lx
u4up8Gk99U3vIK6qY9SzQpB9XLSNTvU/tmx9wQIsiBpSwChIL7/3QSq90SKy+yo8
Fk89frW2Qaf9XPdSCwIDAQAB
-----END PUBLIC KEY-----`
	pubKeyBlock, _ := pem.Decode([]byte(publicKeyData))

	var pub *rsa.PublicKey
	pubInterface, parseErr := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if parseErr != nil {
		fmt.Println("Load public key error")
		panic(parseErr)
	}
	pub = pubInterface.(*rsa.PublicKey)
	encryptedData, encryptErr := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, msgByte, nil)
	if encryptErr != nil {
		fmt.Println("Encrypt data error")
		panic(encryptErr)
	}

	encodedData := base64.URLEncoding.EncodeToString(encryptedData)
	// Encrypted Output (Base64):
	return encodedData
}

func DecryptData(encodedData string) (string, error) {

	encryptedData, _ := base64.URLEncoding.DecodeString(encodedData)

	// privateKeyData, _ := ioutil.ReadFile("private.pem")
	privateKeyData := `-----BEGIN RSA PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALi7SQi91WMeiM54
n3RnL176wjY6/bTXU+KR8RMSNZMNR9M9FNwvd5NlJj1EjBYGBttEvDl6vg8rXGO5
zu0tejl/uXG7i6nwaT31Te8grqpj1LNCkH1ctI1O9T+2bH3BAiyIGlLAKEgvv/dB
Kr3RIrL7KjwWTz1+tbZBp/1c91ILAgMBAAECgYBhF2ZKZuPZhbnnsvQzzOvT4r3i
nNytiKL5KTVojaCE2m0OtELbe0NAv9/6QaXTCXXfFuBK4Z01Adg8PfNpKwbafVMT
akXldHesHaSsm2J6gk5Vxbdj2ZiB/J9E2kbrT3nPF+unMw+uM0BIArZOLd88ug+x
tkjRu0zA4lWb8+J3GQJBAPYbqrbjpFp9qK2MDvZ0z1EPGbT64GxA+JXSWLe8m39Q
hUHaZcc2VQpAmYQYFzW/y1RQ92imp2l1y5ZnS4B8128CQQDAKBWBo+nzQnAtPbNd
E3g0h6FMBjpf1ZOo0D74831XEWHvQEB1s65v1m6FN84MStPm//Jh5/9E6IsIE5J2
10ElAkB7OJz/1vhaKmJDCkYPlaqbTjEz0Qx+hwUvllK/I9rDIuCleSDOXmCzsmZq
odk1GyNFwwgsyIw3nDfjxTIjUd5XAkAmwK69q3IGJjL7XMMslT2b0nKcI3FoXGlg
FUdt66UuhwnqN1oIoskeMu+tHDkIz5p2rs2SIzifDArmARR7tSOlAkEA5P5WRnX1
9OYf/RKkAQND9dbhOVAAFC8LkTL4EjEwDSBN6F7qf+csIqcMy00bpfTg/hHcUxFa
N5hQytwQCE17WQ==
-----END RSA PRIVATE KEY-----`
	privateKeyBlock, _ := pem.Decode([]byte(privateKeyData))

	pri, parseErr := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	key := pri.(*rsa.PrivateKey)

	if parseErr != nil {
		fmt.Println("Load private key error")
		return "", parseErr
	}

	decryptedData, decryptErr := rsa.DecryptOAEP(sha1.New(), rand.Reader, key, encryptedData, nil)

	if decryptErr != nil {
		fmt.Println("Decrypt data error")
		return "", decryptErr
	}
	// Decrypted Output:
	return string(decryptedData), nil
}
