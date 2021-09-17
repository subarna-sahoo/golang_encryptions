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

// package main

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
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCywrBFsxQWNjd0zOxx0ZANIKVk
zQc39bBzX7lZi2O2smDrTeo04r5lTMyDWRg5T36Lcsr+yOKGE/0ff0dI751wi49P
1MwqSKVmZhQeLEz+nhEo0SaIBEel66wPzt99P91ocE9C4G8Cd4fyWz4SnUNhlk0i
9Pi7VvYmslB1INsK9wIDAQAB
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

	return encodedData
}

func DecryptData(encodedData string) (string, error) {

	encryptedData, _ := base64.URLEncoding.DecodeString(encodedData)

	privateKeyData := `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCywrBFsxQWNjd0zOxx0ZANIKVkzQc39bBzX7lZi2O2smDrTeo0
4r5lTMyDWRg5T36Lcsr+yOKGE/0ff0dI751wi49P1MwqSKVmZhQeLEz+nhEo0SaI
BEel66wPzt99P91ocE9C4G8Cd4fyWz4SnUNhlk0i9Pi7VvYmslB1INsK9wIDAQAB
AoGAYZ/fgoEVNDgxuxD7BAHNqM2uZclu6sm7rpaVc+ii8TCjq33mrTEzh8EUY5sx
loLqeh+b6t8sjsq1zxDEjnmFwfogb26D/x2Ks4k4wiITeN+98Lc+UmzqVZORWk2P
H/KbTzzQxE0WGA7F1fpw7ZvrHSsckD4Ilw3tL0Q+ZmSgtPECQQDfzHUMnOf6GBOf
5fNcNtxeEHpn8bmdD4J7nzExdybAawEnlczjkfVnoP419R/UgJpkjj1GiUn+kfrJ
qNi761s5AkEAzHtEXMU5TD44xl08d3uAVZG2Rw1azPP0u0+Rn+EbRM7H5qeV6wzz
gbc2LULEpMcl0nP6WvrEsPXvB5eexqInrwJBAMTG6UQl0nK8KMU3UzuJoUm0A2zR
xfqrYHeCCacMtS4K6AD+XiDafYSYseyPk2UtjpNL3eTfYghMIs6df7P7xUECQALO
EhL/tZiBJgA6mTC+ZfVGiWySF1PGaO4E2meKC/i2qXFVjS3rQI/f9oNKbi4geTlY
0+9Zj0cqKHw/LTNmWAsCQQCtZe4si0lqc5HtfXrf9OII7yssKk+wDQP6gatrT/h/
fP8veEjVG3XI3LtjhJVPDvH+vCMRzNIyKKI8isHk3CAr
-----END RSA PRIVATE KEY-----`
	privateKeyBlock, _ := pem.Decode([]byte(privateKeyData))

	var pri *rsa.PrivateKey
	pri, parseErr := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if parseErr != nil {
		fmt.Println("Load private key error")
		return "", parseErr
	}

	decryptedData, decryptErr := rsa.DecryptOAEP(sha1.New(), rand.Reader, pri, encryptedData, nil)

	if decryptErr != nil {
		fmt.Println("Decrypt data error")
		return "", decryptErr
	}
	// Decrypted Output:
	return string(decryptedData), nil
}
