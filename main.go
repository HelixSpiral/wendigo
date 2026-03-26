package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Issuer    string     `yaml:"Issuer"`
	Providers []Provider `yaml:"Providers"`
}

type Provider struct {
	Name    string `yaml:"Name"`
	Issuer  string `yaml:"Issuer"`
	KeyFile string `yaml:"KeyFile"`
}

func main() {
	cfgFile, err := os.ReadFile("config.yml")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(cfgFile))

	var cfg Config

	err = yaml.Unmarshal(cfgFile, &cfg)
	if err != nil {
		panic(err)
	}

	fmt.Println(cfg)

	http.HandleFunc("/token", func(w http.ResponseWriter, req *http.Request) {
		authHeader, ok := req.Header["Authorization"]
		if !ok {
			fmt.Fprint(w, "No auth header\n")

			return
		}

		fmt.Fprint(w, "Auth header:", authHeader, "\n")

		if len(authHeader) < 1 {
			fmt.Fprint(w, "Auth header invalid\n")

			return
		}

		headerSplit := strings.Split(authHeader[0], " ")
		if len(headerSplit) < 2 {
			fmt.Fprint(w, "Auth header invalid\n")

			return
		}

		rawJwt := headerSplit[1]

		for _, provider := range cfg.Providers {
			token, err := provider.verifyToken(rawJwt)
			if err != nil {
				fmt.Fprint(w, "error verifying token with provider:", provider.Name, "\n")

				continue
			}
			fmt.Fprint(w, provider, token.Header, token.Claims, err)

			newToken := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), token.Claims)
			newToken.Claims.(jwt.MapClaims)["iss"] = cfg.Issuer

			fmt.Fprint(w, provider, newToken.Header, newToken.Claims, err)

			signedToken, err := newToken.SignedString([]byte("Testingstring"))
			if err != nil {
				fmt.Fprintf(w, "Error signing token", err, "\n")

				return
			}

			fmt.Fprint(w, signedToken, "\n")

			return
		}

	})

	http.ListenAndServe(":8090", nil)
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

	token, err := jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %v", token.Header["alg"])
		}

		issuer, err := token.Claims.GetIssuer()
		if err != nil {
			return nil, fmt.Errorf("error getting issuer: %w", err)
		}

		if issuer != p.Issuer {
			return nil, fmt.Errorf("issuer mismatch: %s", issuer)
		}

		return getKeyForToken(token, jwks)
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("failed to validate token")
	}

	return token, nil
}

func getKeyForToken(token *jwt.Token, jwks JWKS) (interface{}, error) {
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
