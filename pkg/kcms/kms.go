/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination mocks/kms_mocks.go -self_package mocks -package mocks -source=kms.go -mock_names VCSKeyManager=MockVCSKeyManager

package kcms

import (
	"crypto/x509"
	"net/http"

	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	"github.com/dellekappa/kcms-go/spi/kms"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
)

type Type string

const (
	AWS   Type = "aws"
	Local Type = "local"
	Web   Type = "web"
)

// Config configure kms that stores signing keys.
type Config struct {
	KMSType     Type `json:"kmsType"`
	Endpoint    string
	Region      string
	AliasPrefix string
	HTTPClient  *http.Client

	SecretLockKeyPath string
	DBType            string
	DBURL             string
	DBName            string
	MasterKey         string
}

type VCSKeyCertManager interface {
	SupportedKeyTypes() []kms.KeyType
	CreateJWKKey(keyType kms.KeyType) (string, *jwk.JWK, error)
	CreateCryptoKey(keyType kms.KeyType) (string, interface{}, error)
	CreateX509Certificate(template *x509.Certificate, key *jwk.JWK) (*x509.Certificate, error)
	NewVCSigner(creator string, signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error)
	GetX509Certificates(chainID string) ([]*x509.Certificate, error)
}
