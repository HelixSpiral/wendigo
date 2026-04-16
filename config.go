package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	Issuer      string       `yaml:"Issuer"`
	Providers   []Provider   `yaml:"Providers"`
	SigningKeys []SigningKey `yaml:"SigningKeys"`
}

type Provider struct {
	Name    string `yaml:"Name"`
	Issuer  string `yaml:"Issuer"`
	KeyFile string `yaml:"KeyFile"`
	Keyfunc jwt.Keyfunc
}

type JWKS struct {
	Keys []JWK
}

type JWK struct {
	Kid string
	Kty string
	N   string
	E   string
}

func (p *Provider) verifyToken(raw string) (*jwt.Token, error) {
	resp, err := http.Get(p.KeyFile)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var jwks JWKS
	err = json.Unmarshal(body, &jwks)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(raw, p.Keyfunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("failed to validate token")
	}

	return token, nil
}

type SigningKey struct {
	ID        string `yaml:"ID"`
	Algorithm string `yaml:"Algorithm"`
	Key       string `yaml:"Key"`
}

func (s *SigningKey) returnJWK() (map[string]string, error) {
	jwk := map[string]string{}
	switch s.Algorithm {
	case "RS256":
		keyFile, err := os.ReadFile(s.Key)
		if err != nil {
			return nil, err
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(keyFile)
		if err != nil {
			return nil, err
		}

		jwk["kty"] = "RSA"
		jwk["kid"] = s.ID
		jwk["use"] = "sig"
		jwk["alg"] = s.Algorithm
		jwk["n"] = base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())

		buf := new(bytes.Buffer)
		err = binary.Write(buf, binary.BigEndian, int64(key.PublicKey.E))
		if err != nil {
			return nil, err
		}
		jwk["e"] = base64.RawURLEncoding.EncodeToString(buf.Bytes())
	default:
		return nil, nil
	}

	return jwk, nil
}
