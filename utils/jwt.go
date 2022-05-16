package utils

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type JWT interface {
	ValidateToken(token string) (*jwt.Token, error)
}

type jwtToken struct {
	secretKey string
	issuer    string
}

func NewJWTService() JWT {
	return &jwtToken{
		issuer:    "trafficviolationsystem",
		secretKey: getSecretKey(),
	}
}

func getSecretKey() string {
	conf := NewConfig()
	secretKey := conf.Database.Secret

	if secretKey != "" {
		secretKey = "trafficviolationsystemjwt"
	}
	return secretKey
}

func (j *jwtToken) ValidateToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t_ *jwt.Token) (interface{}, error) {
		if _, ok := t_.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t_.Header["alg"])
		}
		return []byte(j.secretKey), nil
	})
}
