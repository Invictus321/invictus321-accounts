//+build integration

package accounts

import (
	"testing"
	"time"
)

func Test_Accounts(t *testing.T) {
	as := ServiceFromEnv("testsecret", "abcdefghij1234567890123456789012", 2)

	token1, err := as.CreateUser("testid", "testpassword")
	if err != nil {
		t.Errorf("On create user got error %s", err.Error())
	}

	token2, err := as.Login("testid", "testpassword")
	if err != nil {
		t.Errorf("On login got error %s", err.Error())
	}

	if token2 != token1 {
		t.Errorf("Token from login does not match token from create user")
	}

	_, err = as.Login("testid", "wrongpassword")
	if err == nil {
		t.Errorf("On login with wrong password, didn't get error")
	} else {
		if err.Error() != "Password does not match" {
			t.Errorf("Got wrong error from login with wrong password: %s", err.Error())
		}
	}

	if err := as.ChangePassword(token2, "newpassword"); err != nil {
		t.Errorf("On change password got error %s", err.Error())
	}

	_, err = as.Login("testid", "testpassword")
	if err == nil {
		t.Errorf("On login with old password after change, didn't get error")
	} else {
		if err.Error() != "Password does not match" {
			t.Errorf("Got wrong error from login with old password after change: %s", err.Error())
		}
	}

	token3, err := as.Login("testid", "newpassword")
	if err != nil {
		t.Errorf("On login with new password got error %s", err.Error())
	}
	if token3 != token1 {
		t.Errorf("Token from login with new password does not match token from create user")
	}

	id, err := as.Authorise(token3)
	if err != nil {
		t.Errorf("On authorise got error %s", err.Error())
	}
	if id != "testid" {
		t.Errorf("Id from authorise did not match test id: %s", id)
	}

	time.Sleep(3 * time.Second)

	_, err = as.Authorise(token3)
	if err == nil {
		t.Errorf("On authorise with expired token, didn't get error")
	}
	if err.Error() != "token is too old" {
		t.Errorf("Got wrong error from authorise with expired token: %s", err.Error())
	}

	_, err = as.Authorise("gibberish")
	if err == nil {
		t.Errorf("On authorise with invalid token, didn't get error")
	}

	err = as.DeleteUser("testid")
	if err != nil {
		t.Errorf("On delete user got error %s", err.Error())
	}

	_, err = as.Login("testid", "newpassword")
	if err == nil {
		t.Errorf("On login to deleted user, didn't get error")
	}
}
