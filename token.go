package LoginSignup

import (
	"encoding/base64"
	"errors"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var errGenToken = errors.New("Error in token generation please try again")
var errGenHash = errors.New("Error in generating hash for email id")

func GenerateHash(value string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(value), bcrypt.DefaultCost)
	if err != nil {
		return "", errGenHash
	}
	return string(hash), nil
}

func GenerateToken(emailID string) string {
	return base64.StdEncoding.EncodeToString([]byte(emailID))
}

type Claims struct {
	UserName string `json:"username"`
	jwt.StandardClaims
}
