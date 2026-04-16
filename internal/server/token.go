package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type tokenResponse struct {
	Token   string `json:"access_token"`
	Type    string `json:"token_type"`
	Expiers int64  `json:"expires_in"`
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

func (s *Server) TokenHandler(w http.ResponseWriter, req *http.Request) {
	authHeader, ok := req.Header["Authorization"]
	if !ok {
		slog.Warn("Request missing authorization header", "path", req.URL.Path)
		http.Error(w, "No auth header", http.StatusUnauthorized)
		return
	}

	if len(authHeader) < 1 {
		slog.Warn("Authorization header is empty", "path", req.URL.Path)
		http.Error(w, "Auth header invalid", http.StatusUnauthorized)
		return
	}

	slog.Info("authorization header received", "path", req.URL.Path)

	headerSplit := strings.Split(authHeader[0], " ")
	if len(headerSplit) < 2 {
		slog.Warn("Authorization header format invalid", "path", req.URL.Path)
		http.Error(w, "Auth header invalid", http.StatusUnauthorized)
		return
	}

	rawJwt := headerSplit[1]

	for _, provider := range s.providers {
		token, err := s.verifyToken(provider, rawJwt)
		if err != nil {
			slog.Warn("failed to verify token with provider", "provider", provider.Name, "error", err)
			continue
		}

		slog.Info("token verified successfully", "provider", provider.Name)

		newToken := jwt.NewWithClaims(jwt.GetSigningMethod(s.signingKeys[0].Algorithm), token.Claims)
		newToken.Claims.(jwt.MapClaims)["iss"] = s.issuer
		newToken.Header["kid"] = s.signingKeys[0].ID

		slog.Info("new token created", "provider", provider.Name, "algorithm", s.signingKeys[0].Algorithm)

		var signedToken string

		switch s.signingKeys[0].Algorithm {
		case "HS256", "HS384", "HS512":
			signedToken, err = newToken.SignedString([]byte(s.signingKeys[0].Key))
		case "RS256", "RS384", "RS512":
			keyFile, err := os.ReadFile(s.signingKeys[0].Key)
			if err != nil {
				slog.Error("failed to read signing key file", "path", s.signingKeys[0].Key, "error", err)
				http.Error(w, "error reading key file", http.StatusInternalServerError)

				return
			}
			key, err := jwt.ParseRSAPrivateKeyFromPEM(keyFile)
			if err != nil {
				slog.Error("failed to parse RSA private key", "error", err)
				http.Error(w, "error parsing key", http.StatusInternalServerError)

				return
			}
			signedToken, err = newToken.SignedString(key)
		}

		returnMessage := &tokenResponse{
			Token:   signedToken,
			Type:    "Bearer",
			Expiers: 600,
		}

		if err != nil {
			slog.Error("failed to sign token", "algorithm", s.signingKeys[0].Algorithm, "error", err)
			http.Error(w, "error signing token", http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(returnMessage); err != nil {
			slog.Error("error encoding response", "error", err)

			http.Error(w, "error returning token", http.StatusInternalServerError)

			return
		}

		slog.Info("token signed and returned successfully", "provider", provider.Name)

		return
	}

	// If we reach here, no provider could verify the token.
	slog.Warn("no provider could verify the token", "path", req.URL.Path)

	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (s *Server) verifyToken(p Provider, raw string) (*jwt.Token, error) {
	token, err := jwt.Parse(raw, p.Keyfunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("failed to validate token")
	}

	return token, nil
}
