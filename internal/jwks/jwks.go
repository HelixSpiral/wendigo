package jwks

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/helixspiral/wendigo/internal/config"
)

func FromSigningKey(sk config.SigningKey) (map[string]string, error) {
	jwk := map[string]string{}
	switch sk.Algorithm {
	case "RS256":
		keyFile, err := os.ReadFile(sk.Key)
		if err != nil {
			return nil, err
		}
		key, err := jwt.ParseRSAPrivateKeyFromPEM(keyFile)
		if err != nil {
			return nil, err
		}

		jwk["kty"] = "RSA"
		jwk["kid"] = sk.ID
		jwk["use"] = "sig"
		jwk["alg"] = sk.Algorithm
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
