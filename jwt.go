package main

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

type JWKS struct {
	Keys []JWK
}

type JWK struct {
	Kid string
	Kty string
	N   string
	E   string
}

func getKeyForToken(token *jwt.Token, jwks JWKS) (any, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token mising kid")
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return getRSAPublicKey(key)
		}
	}

	return nil, fmt.Errorf("no matching key found")
}

func getRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	eInt := 0
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}
