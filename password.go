package accounts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

func (a accountService) hashPassword(password string, salt []byte) (passwordHash []byte, err error) {
	passwordKey := base64.StdEncoding.EncodeToString(pbkdf2.Key([]byte(password), salt, 3000, 16, sha1.New))
	passwordHash, err = encrypt(a.encryptionKey, []byte(passwordKey))
	return
}

func (a accountService) comparePasswords(password string, encryptedPassword, salt []byte) error {
	passwordKey := base64.StdEncoding.EncodeToString(pbkdf2.Key([]byte(password), salt, 3000, 16, sha1.New))
	decryptedPassword, err := decrypt(a.encryptionKey, encryptedPassword)
	if err != nil {
		return err
	}
	if string(decryptedPassword) != passwordKey {
		return IncorrectPassword{fmt.Errorf("Password does not match")}
	}
	return nil
}

func (a accountService) generateSalt() []byte {
	b := make([]byte, 16)
	rand.Read(b)
	return b
}

func encrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	b := base64.StdEncoding.EncodeToString(text)
	ciphertext := make([]byte, aes.BlockSize+len(b))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
	return ciphertext, nil
}

func decrypt(key, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}
	return data, nil
}
