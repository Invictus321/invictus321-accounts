package db

type Account struct {
	Id           string
	Salt         []byte
	PasswordHash []byte
}
