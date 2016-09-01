package accounts

import (
	"fmt"
	"time"

	"gopkg.in/dgrijalva/jwt-go.v2"
)

type InvalidToken struct{ error }
type ExpiredToken struct{ error }
type MissingToken struct{ error }

func (a accountService) createToken(id string) (token string, err error) {
	jwToken := jwt.New(jwt.GetSigningMethod("HS256"))
	jwToken.Claims["id"] = id
	jwToken.Claims["expiry"] = time.Now().Unix() + a.lifeSpan
	token, err = jwToken.SignedString(a.secret)
	return
}

func (a accountService) getKey(token *jwt.Token) (interface{}, error) {
	if alg := token.Method.Alg(); alg != "HS256" {
		return nil, InvalidToken{fmt.Errorf("unsupported algorithm %s", alg)}
	}
	return a.secret, nil
}

func (a accountService) decodeToken(token string) (id string, err error) {
	if token == "" {
		return "", MissingToken{fmt.Errorf("Token is blank")}
	}
	jwToken, err := jwt.Parse(token, a.getKey)
	if err != nil {
		return
	}
	if expiryClaim, ok := jwToken.Claims["expiry"]; ok {
		if expiryF, ok := expiryClaim.(float64); ok {
			expiry := int64(expiryF)
			if expiry < time.Now().Unix() {
				return "", ExpiredToken{fmt.Errorf("token is too old")}
			}
		} else {
			return "", InvalidToken{fmt.Errorf("token expiry is an invalid data type")}
		}
	} else {
		return "", InvalidToken{fmt.Errorf("token expiry is missing")}
	}
	if idClaim, ok := jwToken.Claims["id"]; ok {
		if stringId, ok := idClaim.(string); ok {
			id = stringId
		} else {
			return "", InvalidToken{fmt.Errorf("token id is an invalid data type")}
		}
	} else {
		return "", InvalidToken{fmt.Errorf("token id is missing")}
	}
	return
}
