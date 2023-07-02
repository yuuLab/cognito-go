package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

type jwks struct {
	Keys []json.RawMessage `json:"keys"`
}

type jwk struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	E   string `json:"e"`
	N   string `json:"n"`
	Use string `json:"use"`
}

// Validaet IdToken.
func ValidateIdToken(idToken *string) error {
	parsedToken, err := jwt.Parse(*idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		body, err := getJWKS()
		if err != nil {
			return nil, err
		}

		var jwks jwks
		if err := json.Unmarshal(body, &jwks); err != nil {
			return nil, fmt.Errorf("error parsing JWKS: %w", err)
		}
		for _, key := range jwks.Keys {
			var jwk jwk
			err = json.Unmarshal(key, &jwk)
			if err != nil {
				return nil, fmt.Errorf("error parsing JWK key: %w", err)
			}
			if token.Header["kid"] == jwk.Kid {
				return createRSAPublicKey(jwk)
			}
		}
		return nil, fmt.Errorf("unable to find appropriate key")
	}, jwt.WithAudience(cognitoClientId), jwt.WithIssuer(issuer))

	if err != nil {
		return errors.Wrapf(err, "idToken is invalid")
	}
	if !parsedToken.Valid {
		return fmt.Errorf("failed to parse token")
	}

	claims := parsedToken.Claims.(jwt.MapClaims)
	// verify tokent_use (allow only "id")
	if tokenUse, ok := claims["token_use"].(string); ok && tokenUse == "id" {
		// IdToken is valid
		return nil
	} else {
		return fmt.Errorf("IdTokenのClaimからtoken_useの値が不正です。%v", tokenUse)
	}
}

// Download and store the corresponding public JSON Web Key (JWK) for your user pool.
func getJWKS() ([]byte, error) {
	// TODO: Implement caching
	resp, err := http.Get(jwksPoint)
	if err != nil {
		return nil, errors.Wrapf(err, "Error fetching public keys from %s", jwksPoint)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	return body, nil
}

// Generate an RSA public key from the jwk modulus N and exponent E.
func createRSAPublicKey(jwk jwk) (*rsa.PublicKey, error) {
	decordedN, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	decordedE, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}
	nBigInt := new(big.Int).SetBytes(decordedN)
	eBigInt := new(big.Int).SetBytes(decordedE)
	eInt := int(eBigInt.Int64())
	publicKey := &rsa.PublicKey{
		N: nBigInt,
		E: eInt,
	}
	return publicKey, nil
}
