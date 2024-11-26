/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcskcms

import (
	"crypto/x509"

	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	mockwrapper "github.com/dellekappa/kcms-go/mock/wrapper"
	kmsapi "github.com/dellekappa/kcms-go/spi/kms"
	"github.com/dellekappa/kcms-go/suite/api"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kcms"
	"github.com/trustbloc/vcs/pkg/kcms/signer"
)

// MockKCMS mocks kcms.VCSKeyCertManager.
//
// Set either MockKCMS.Signer or MockKCMS.FixedSigner.
type MockKCMS struct {
	Signer      api.KMSCryptoMultiSigner
	FixedSigner api.FixedKeyMultiSigner
	VCSignerErr error
	KeyTypes    []kmsapi.KeyType
}

// NewVCSigner mock.
func (m *MockKCMS) NewVCSigner(creator string, signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error) {
	if m.VCSignerErr != nil {
		return nil, m.VCSignerErr
	}

	var (
		fks api.FixedKeyMultiSigner
		err error
	)

	switch {
	case m.FixedSigner != nil:
		fks = m.FixedSigner
	case m.Signer != nil:
		fks, err = m.Signer.FixedMultiSignerGivenKID(creator)
		if err != nil {
			return nil, err
		}
	default:
		fks = &mockwrapper.MockFixedKeyCrypto{}
	}

	return signer.NewKMSSignerBBS(fks, signatureType, nil), nil
}

// SupportedKeyTypes unimplemented stub.
func (m *MockKCMS) SupportedKeyTypes() []kmsapi.KeyType {
	return m.KeyTypes
}

// CreateJWKKey unimplemented stub.
func (m *MockKCMS) CreateJWKKey(_ kmsapi.KeyType) (string, *jwk.JWK, error) {
	return "", nil, nil
}

// CreateCryptoKey unimplemented stub.
func (m *MockKCMS) CreateCryptoKey(_ kmsapi.KeyType) (string, interface{}, error) {
	return "", nil, nil
}

func (m *MockKCMS) CreateX509Certificate(_ *x509.Certificate, _ *jwk.JWK) (*x509.Certificate, error) {
	return nil, nil //nolint:nilnil
}

func (m *MockKCMS) GetX509Certificates(_ string) ([]*x509.Certificate, error) {
	return nil, nil //nolint:nilnil
}

var _ kcms.VCSKeyCertManager = &MockKCMS{}
