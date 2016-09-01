package db

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

type NoDatabaseUrl struct{ error }

type DbService interface {
	GetUserById(id string) (Account, error)
	UpdateUser(account Account) error
	CreateUser(account Account) error
	DeleteUserById(id string) error
}

type dbService struct {
	dbConn *sql.DB
}

func (d dbService) GetUserById(id string) (Account, error) {
	account := Account{Id: id}
	if err := d.dbConn.QueryRow("SELECT salt, password_hash FROM account WHERE id = $1", id).Scan(&account.Salt, &account.PasswordHash); err != nil {
		return account, err
	}
	return account, nil
}

func (d dbService) UpdateUser(account Account) error {
	_, err := d.dbConn.Exec("UPDATE account set salt = $1, password_hash = $2 WHERE id = $3", account.Salt, account.PasswordHash, account.Id)
	return err
}

func (d dbService) CreateUser(account Account) error {
	_, err := d.dbConn.Exec("INSERT INTO account (id, salt, password_hash) VALUES ($1, $2, $3)", account.Id, account.Salt, account.PasswordHash)
	return err
}

func (d dbService) DeleteUserById(id string) error {
	_, err := d.dbConn.Exec("DELETE FROM account WHERE id = $1", id)
	return err
}

func DbServiceFromEnv() (DbService, error) {
	url := os.Getenv("ACCOUNTS_DATABASE_URL")
	if len(url) == 0 {
		return nil, NoDatabaseUrl{fmt.Errorf("No postgres database url in environment variables - please set ACCOUNTS_DATABASE_URL")}
	}
	dbConn, err := sql.Open("postgres", url)
	if err != nil {
		return nil, err
	}
	return dbService{dbConn}, nil
}
