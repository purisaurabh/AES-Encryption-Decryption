package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// 32 bytes for the AES-256 encryption
var key = []byte("abcdefghijklmnopqrstuvwxyz123456")

// This function is used to ensure that the key is always 32 bytes by hashing an input the key using SHA-256 which produces a 32 byte (256 bit) hash
func GenerateKey() []byte {
	hash := sha256.Sum256(key)
	fmt.Println("hash is : ", hash)
	return hash[:]
}

// Encrypt encrypts the given string using AES-256 encryption
func Encrypt(data string) (string, error) {
	key := GenerateKey()

	// creating the new cipher block
	// A block cipher is a type of encryption algorithm that transform a fixed size block of plaintest data into a block of ciphertext data of the same size using symmetric key
	// The data to be encrypted is divider into fixed size block
	// If the data is not a multiple of the block size , padding is assed to the last block to make it correct size

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("error in creating new cipher: ", err)
		return "", err
	}

	// Block cipher uses different modes of operation to encrypt the data larger than the block size and the enhance security
	// a) ECB (Electronic Code Book) mode
	// b) CBC (Cipher Block Chaining) mode
	// c) GCM (Galois/Counter Mode)

	// this is used to :
	// NewGCM function is used to create the Galois/Counter Mode cipher
	// GCM is a mode of operations for symmetric key cryptographic block ciphers that provides both data confidentiality and authentication
	// GCM requires unique nonce or initialization vector for every encryption operation
	// The nonce ensures that the same plaintext encrypted multiple time will produce different ciphertexts , enhancing the security
	// GCM not only encrypt the data but also generates an authentication tag ensures that the data has not need tempered with during transmission

	// Each block is encrypted using the block cipher in counter mode.This mode turn the block cipher into a stream cipher allowing it to encrypt data of any length
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("error in creating new GCM: ", err)
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	fmt.Println("nonce size: ", aesGCM.NonceSize())
	fmt.Println("nonce: ", nonce)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println("error in reading random data: ", err)
		return "", err
	}

	// Seal perform both encryption and authentication in one step
	// Parameter :
	// 1) destination : the destination slice to which the result will be appended, in this nonce will used as the destination meaning the nonce will be prepended to the ciphertext
	// 2) nonce : unique value for every encryption operation
	// 3) plaintext : the data to be encrypted
	// 4) additionalData : additional data that will be authenticated but not encrypted
	// The seal function return a byte slice containing the nonce followed bu the ciphertext adn the authentication tag.
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(data), nil)
	fmt.Println("ciphertext: ", ciphertext)
	fmt.Println("ciphertext in string: ", base64.StdEncoding.EncodeToString(ciphertext))
	// ciphertext made up of binary data to convert it to string we use base64 encoding
	// The base64-encoded string can be included in JSON responses, stored in databases, or transmitted over HTTP without any issues related to non-printable characters.
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func Decrypt(cipherText string) (string, error) {
	key := GenerateKey()
	decodeCipherText, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		fmt.Println("error in decoding cipher text: ", err)
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("error in creating new cipher: ", err)
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println("error in creating new GCM: ", err)
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, cipherTextBytes := decodeCipherText[:nonceSize], decodeCipherText[nonceSize:]

	plainTextBytes, err := aesGCM.Open(nil, nonce, cipherTextBytes, nil)
	if err != nil {
		fmt.Println("error in decrypting data: ", err)
		return "", err
	}

	return string(plainTextBytes), nil
}
