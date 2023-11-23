package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
)

func encode(videoPath string, filename string, passphrase string) error {
	videoBytes, err := os.ReadFile(videoPath)
	if err != nil {
		return err
	}

	videoBase64 := base64.StdEncoding.EncodeToString(videoBytes)

	encrypted, err := encrypt([]byte(videoBase64), passphrase)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, []byte(encrypted), 0644)
	if err != nil {
		return err
	}

	return nil
}

func decode(encodedPath string, filename string, passphrase string) error {
	videoBase64, err := os.ReadFile(encodedPath)
	if err != nil {
		return err
	}

	decryptedBytes, err := decrypt([]byte(videoBase64), passphrase)
	if err != nil {
		return err
	}

	videoBytes, err := base64.StdEncoding.DecodeString(string(decryptedBytes))
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, videoBytes, 0644)
	if err != nil {
		return err
	}

	return nil
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(passphrase))
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("invalid decryption")
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

func generatePassphrase(length int) string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	charsetLen := big.NewInt(int64(len(charset)))

	randomString := make([]byte, length)
	for i := range randomString {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			panic(err)
		}
		randomString[i] = charset[randomIndex.Int64()]
	}

	return string(randomString)
}

func main() {
	option := flag.String("t", "", "Could be gen, enc, dec")
	source := flag.String("s", "", "Path of the source/encrypted file")
	output := flag.String("o", "", "Path of the output file")
	passphrase := flag.String("k", "", "Key of 16 characters")

	flag.Parse()

	switch *option {
	case "":
		fmt.Println("-t should be gen, enc or dec")
		return
	case "gen":
		key := generatePassphrase(16)
		fmt.Println(key)
	case "enc":
		if *source == "" {
			fmt.Println("-s should not be empty")
			return
		}

		if *output == "" {
			fmt.Println("-o should not be empty")
			return
		}

		if *passphrase == "" {
			fmt.Println("-k should not be empty")
			return
		}

		err := encode(*source, *output, *passphrase)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("%s encrypted and created successfully\n", *output)
	case "dec":
		if *source == "" {
			fmt.Println("-s should not be empty")
			return
		}

		if *output == "" {
			fmt.Println("-o should not be empty")
			return
		}

		if *passphrase == "" {
			fmt.Println("-k should not be empty")
			return
		}

		err := decode(*source, *output, *passphrase)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("%s decrypted and created successfully\n", *output)
	}
}
