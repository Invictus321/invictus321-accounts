package accounts

import "github.com/invictus321/invictus321-accounts/db"

type AccountExists struct{ error }
type IncorrectPassword struct{ error }
type UnauthorisedToken struct{ error }

type Service interface {
	Login(id, password string) (token string, err error)
	Authorise(token string) (id string, err error)
	ChangePassword(token, password string) error
	CreateUser(id, password string) (token string, err error)
	DeleteUser(id string) error
}

type accountService struct {
	dbService     db.DbService
	secret        []byte
	encryptionKey []byte
	lifeSpan      int64
}

func (a accountService) Login(id, password string) (token string, err error) {
	account, err := a.dbService.GetUserById(id)
	if err != nil {
		return
	}
	err = a.comparePasswords(password, account.PasswordHash, account.Salt)
	if err == nil {
		token, err = a.createToken(id)
	}
	return
}

func (a accountService) Authorise(token string) (id string, err error) {
	id, err = a.decodeToken(token)
	return
}

func (a accountService) ChangePassword(token, password string) error {
	salt := a.generateSalt()
	passwordHash, err := a.hashPassword(password, salt)
	if err != nil {
		return err
	}
	id, err := a.decodeToken(token)
	if err != nil {
		return UnauthorisedToken{err}
	}
	if err := a.dbService.UpdateUser(db.Account{Id: id, Salt: salt, PasswordHash: passwordHash}); err != nil {
		return err
	}
	return nil
}

func (a accountService) CreateUser(id, password string) (token string, err error) {
	salt := a.generateSalt()
	passwordHash, err := a.hashPassword(password, salt)
	if err != nil {
		return "", err
	}
	createError := a.dbService.CreateUser(db.Account{Id: id, Salt: salt, PasswordHash: passwordHash})
	if createError != nil {
		err = AccountExists{createError}
	} else {
		token, err = a.createToken(id)
	}
	return
}

func (a accountService) DeleteUser(id string) error {
	return a.dbService.DeleteUserById(id)
}

func ServiceFromEnv(secret, encryptionKey string, lifeSpan int64) Service {
	dbServ, err := db.DbServiceFromEnv()
	if err != nil {
		panic(err)
	}
	return accountService{
		dbServ,
		[]byte(secret),
		[]byte(encryptionKey),
		lifeSpan,
	}
}
