package asymmetric

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"mannemsolutions/pgcustodian/pkg/utils"
	"os"
	"path/filepath"
)

func GeneratePrivateKey(privateKeyPath string) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("unable to generate private key: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("unable to write private key: %w", err)
	}
	return privateKey, nil
}

func ReadPrivateKeyFromFile(privateKeyPath string) (*rsa.PrivateKey, error) {
	if privateKeyPath == "" {
		return nil, fmt.Errorf("cannot get private key without a specified path")
	}
	if privateKeyPem, err := os.ReadFile(privateKeyPath); err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	} else if privateKeyBlock, _ := pem.Decode(privateKeyPem); privateKeyBlock == nil {
		return nil, fmt.Errorf("cannot decode private key")
	} else if privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes); err != nil {
		return nil, fmt.Errorf("private key invalid: %w", err)
	} else {
		return privateKey, nil
	}
}

func PrivateToPublic(privateKey *rsa.PrivateKey, publicKeyPath string) (*rsa.PublicKey, error) {
	if publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey); err != nil {
		return nil, fmt.Errorf("unable to marshal public key: %w", err)
	} else {
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		if publicKeyPath != "" {
			if err = os.WriteFile(publicKeyPath, publicKeyPEM, 0o600); err != nil {
				return nil, fmt.Errorf("unable to write public key: %w", err)
			}
		}
	}
	return &privateKey.PublicKey, nil
}

func ReadPublicKeyFromFile(publicKeyPath string) (*rsa.PublicKey, error) {
	if publicKeyPEM, err := os.ReadFile(publicKeyPath); err != nil {
		return nil, err
	} else if publicKeyBlock, _ := pem.Decode(publicKeyPEM); publicKeyBlock == nil {
		return nil, fmt.Errorf("cannot decode public key")
	} else if publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes); err != nil {
		return nil, fmt.Errorf("public key invalid: %w", err)
	} else if publicRsaKey, ok := publicKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("public key not rsa public key")
	} else {
		return publicRsaKey, nil
	}
}

func Decrypt(key *rsa.PrivateKey, data []byte, label string) (decrypted []byte, err error) {
	if key == nil {
		return nil, fmt.Errorf("cannot encrypt without a private key")
	}
	if data == nil {
		return nil, fmt.Errorf("cannot decrypt nil data")
	}
	decrypted, err = rsa.DecryptOAEP(sha256.New(), nil, key, data, []byte(label))
	if err != nil {
		return nil, fmt.Errorf("Error while decrypting data: %w", err)
	}
	return decrypted, nil
}

func DecryptFromFile(key *rsa.PrivateKey, path string, label string) (decrypted []byte, err error) {
	if path == "" {
		return nil, fmt.Errorf("cannot get data to decrypt without a specified path")
	}
	if data, err := os.ReadFile(path); err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	} else if decrypted, err := Decrypt(key, data, label); err != nil {
		return nil, fmt.Errorf("failed to decrypt file: %w", err)
	} else {
		return decrypted, nil
	}
}

func Encrypt(key *rsa.PublicKey, data []byte, label string) (encrypted []byte, err error) {
	if key == nil {
		return nil, fmt.Errorf("cannot encrypt without a public key")
	}
	if data == nil {
		return nil, fmt.Errorf("cannot encrypt nil data")
	}
	encrypted, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, key, data, []byte(label))
	if err != nil {
		return nil, fmt.Errorf("error while encrypting data: %w", err)
	}
	return encrypted, nil
}

func EncryptToFile(key *rsa.PublicKey, path string, label string, decrypted []byte) (err error) {
	if path == "" {
		return fmt.Errorf("cannot write encrypted data to file unless a path is specified")
	}
	if err = utils.MakeTree(filepath.Dir(path)); err != nil {
		return fmt.Errorf("dir %s does not exist annd could not be created: %w", path, err)
	}
	if encrypted, err := Encrypt(key, decrypted, label); err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	} else if err := os.WriteFile(path, encrypted, 0o600); err != nil {
		return fmt.Errorf("unable to write to encrypted key file: %w", err)
	}
	return nil
}
