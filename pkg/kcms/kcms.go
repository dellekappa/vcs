/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kcms

import (
	"context"
	"crypto/x509"
	"fmt"
	cmsapi "github.com/dellekappa/kcms-go/spi/cms"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/cmsstore"
	"io"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/dellekappa/did-go/legacy/mem"
	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	arieskms "github.com/dellekappa/kcms-go/kms"
	"github.com/dellekappa/kcms-go/secretlock/local"
	kmsapi "github.com/dellekappa/kcms-go/spi/kms"
	"github.com/dellekappa/kcms-go/spi/secretlock"
	"github.com/dellekappa/kcms-go/suite/api"
	"github.com/dellekappa/kcms-go/suite/localsuite"
	"github.com/dellekappa/kcms-go/suite/websuite"

	awssvc "github.com/trustbloc/vcs/pkg/kcms/aws"
	"github.com/trustbloc/vcs/pkg/storage/mongodb"
	"github.com/trustbloc/vcs/pkg/storage/mongodb/arieskmsstore"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	vcsverifiable "github.com/trustbloc/vcs/pkg/doc/verifiable"
	"github.com/trustbloc/vcs/pkg/kcms/key"
	"github.com/trustbloc/vcs/pkg/kcms/signer"
)

// nolint: gochecknoglobals
var ariesSupportedKeyTypes = []kmsapi.KeyType{
	kmsapi.ED25519Type,
	kmsapi.X25519ECDHKWType,
	kmsapi.ECDSASecp256k1TypeIEEEP1363,
	kmsapi.ECDSAP256TypeDER,
	kmsapi.ECDSAP384TypeDER,
	kmsapi.RSAPS256Type,
	kmsapi.BLS12381G2Type,
}

// nolint: gochecknoglobals
var awsSupportedKeyTypes = []kmsapi.KeyType{
	kmsapi.ECDSAP256TypeDER,
	kmsapi.ECDSAP384TypeDER,
	kmsapi.ECDSASecp256k1DER,
}

const (
	keystoreLocalPrimaryKeyURI = "local-lock://keystorekms"
	storageTypeMemOption       = "mem"
	storageTypeMongoDBOption   = "mongodb"
)

type metricsProvider interface {
	SignTime(value time.Duration)
}

type KeyCertManager struct {
	kmsType Type
	metrics metricsProvider
	suite   api.Suite
}

func GetAriesKeyCertManager(suite api.Suite, kmsType Type, metrics metricsProvider) *KeyCertManager {
	return &KeyCertManager{
		suite:   suite,
		kmsType: kmsType,
		metrics: metrics,
	}
}

func NewAriesKeyCertManager(cfg *Config, metrics metricsProvider) (*KeyCertManager, error) {
	switch cfg.KMSType {
	case Local:
		suite, err := createLocalKCMSSuite(cfg)
		if err != nil {
			return nil, err
		}

		return &KeyCertManager{
			kmsType: cfg.KMSType,
			metrics: metrics,
			suite:   suite,
		}, nil
	case Web:
		return &KeyCertManager{
			kmsType: cfg.KMSType,
			metrics: metrics,
			suite:   websuite.NewWebCryptoSuite(cfg.Endpoint, cfg.HTTPClient),
		}, nil
	case AWS:
		awsConfig, err := config.LoadDefaultConfig(
			context.Background(),
		)
		if err != nil {
			return nil, err
		}

		opts := []awssvc.Opts{
			awssvc.WithKeyAliasPrefix(cfg.AliasPrefix),
		}

		if cfg.Endpoint != "" {
			opts = append(opts, awssvc.WithAWSEndpointResolverV2(&EndpointResolver{
				Endpoint: cfg.Endpoint,
			}))
		}

		awsSuite := awssvc.NewSuite(&awsConfig, nil, "", opts...)

		return &KeyCertManager{
			kmsType: cfg.KMSType,
			metrics: metrics,
			suite:   awsSuite,
		}, nil
	}

	return nil, fmt.Errorf("unsupported kms type: %s", cfg.KMSType)
}

func createLocalKCMSSuite(cfg *Config) (api.Suite, error) {
	secretLockService, err := createLocalSecretLock(
		cfg.SecretLockKeyPath,
		cfg.MasterKey,
	)
	if err != nil {
		return nil, err
	}

	kmsStore, err := createKMSStore(cfg.DBType, cfg.DBURL, cfg.DBName)
	if err != nil {
		return nil, err
	}

	cmsStore, err := createCMSStore(cfg.DBType, cfg.DBURL, cfg.DBName)
	if err != nil {
		return nil, err
	}

	return localsuite.NewLocalKCMSSuite(keystoreLocalPrimaryKeyURI, kmsStore, cmsStore, secretLockService)
}

func (km *KeyCertManager) SupportedKeyTypes() []kmsapi.KeyType {
	if km.kmsType == AWS {
		return awsSupportedKeyTypes
	}

	return ariesSupportedKeyTypes
}

func (km *KeyCertManager) Suite() api.Suite {
	return km.suite
}

func (km *KeyCertManager) CreateJWKKey(keyType kmsapi.KeyType) (string, *jwk.JWK, error) {
	creator, err := km.Suite().KeyCreator()
	if err != nil {
		return "", nil, err
	}

	return key.JWKKeyCreator(creator)(keyType)
}

func (km *KeyCertManager) CreateCryptoKey(keyType kmsapi.KeyType) (string, interface{}, error) {
	creator, err := km.Suite().RawKeyCreator()
	if err != nil {
		return "", nil, err
	}

	return key.CryptoKeyCreator(creator)(keyType)
}

func (km *KeyCertManager) CreateX509Certificate(template *x509.Certificate, key *jwk.JWK) (*x509.Certificate, error) {
	creator, err := km.Suite().CMSCertIssuer()
	if err != nil {
		return nil, err
	}

	return creator.IssueCertificate(template, key)
}

func (km *KeyCertManager) NewVCSigner(
	creator string, signatureType vcsverifiable.SignatureType) (vc.SignerAlgorithm, error) {
	if signatureType == vcsverifiable.BbsBlsSignature2020 {
		fks, err := km.Suite().FixedKeyMultiSigner(creator)
		if err != nil {
			return nil, err
		}

		return signer.NewKMSSignerBBS(fks, signatureType, km.metrics), nil
	}

	fks, err := km.Suite().FixedKeySigner(creator)
	if err != nil {
		return nil, err
	}

	return signer.NewKMSSigner(fks, signatureType, km.metrics), nil
}

func (km *KeyCertManager) GetX509Certificates(chainID string) ([]*x509.Certificate, error) {
	getter, err := km.suite.CMSCertGetter()
	if err != nil {
		return nil, err
	}
	return getter.GetCertificates(chainID)
}

func createLocalSecretLock(
	keyPath string,
	kmsMasterKey string,
) (secretlock.Service, error) {
	var err error
	var primaryKeyReader io.Reader

	if kmsMasterKey != "" {
		primaryKeyReader = strings.NewReader(kmsMasterKey)
	} else {
		if keyPath == "" {
			return nil, fmt.Errorf("no key defined for local secret lock")
		}
		primaryKeyReader, err = local.MasterKeyFromPath(keyPath)
		if err != nil {
			return nil, err
		}
	}

	secretLock, err := local.NewService(primaryKeyReader, nil)
	if err != nil {
		return nil, err
	}

	return secretLock, nil
}

func createKMSStore(typ, url, prefix string) (kmsapi.Store, error) {
	switch {
	case strings.EqualFold(typ, storageTypeMemOption):
		return arieskms.NewAriesProviderWrapper(mem.NewProvider())
	case strings.EqualFold(typ, storageTypeMongoDBOption):
		mongoClient, err := mongodb.New(url, fmt.Sprintf("%s%s", prefix, "kms_db"))
		if err != nil {
			return nil, err
		}

		return arieskmsstore.NewStore(mongoClient), nil
	default:
		return nil, fmt.Errorf("not supported database type: %s", typ)
	}
}

func createCMSStore(typ, url, prefix string) (cmsapi.Store, error) {
	switch {
	case strings.EqualFold(typ, storageTypeMemOption):
		return nil, fmt.Errorf("database type %s not yet implemented", typ)
	case strings.EqualFold(typ, storageTypeMongoDBOption):
		mongoClient, err := mongodb.New(url, fmt.Sprintf("%s%s", prefix, "cms_db"))
		if err != nil {
			return nil, err
		}

		return cmsstore.NewStore(mongoClient), nil
	default:
		return nil, fmt.Errorf("not supported database type: %s", typ)
	}
}
