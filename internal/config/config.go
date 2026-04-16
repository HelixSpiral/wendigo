package config

import "github.com/golang-jwt/jwt/v5"

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

type SigningKey struct {
	ID        string `yaml:"ID"`
	Algorithm string `yaml:"Algorithm"`
	Key       string `yaml:"Key"`
}
