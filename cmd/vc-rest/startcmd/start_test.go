/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	ariesmockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/vcs/cmd/common"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host string, handler http.Handler) error {
	return nil
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start vc-rest", startCmd.Short)
	require.Equal(t, "Start vc-rest inside the vcs", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "host-url value is empty", err.Error())
	})

	t.Run("test blank bloc domain arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "test", "--" + blocDomainFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "bloc-domain value is empty", err.Error())
	})

	t.Run("test blank database type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "test",
			"--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "database-type value is empty", err.Error())
	})

	t.Run("test blank mode type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "test",
			"--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + modeFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "mode value is empty", err.Error())
	})

	t.Run("invalid mode", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "test",
			"--" + blocDomainFlagName, "domain", "--" + databaseTypeFlagName, databaseTypeMemOption,
			"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + modeFlagName, "invalid",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported mode")
	})
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := startCmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither host-url (command line flag) nor VC_REST_HOST_URL (environment variable) have been set.",
			err.Error())
	})
}

func TestStartCmdWithBlankEnvVar(t *testing.T) {
	t.Run("test blank host env var", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "")
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "VC_REST_HOST_URL value is empty", err.Error())
	})
}

func TestStartCmdCreateKMSFailure(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080", "--" + blocDomainFlagName, "domain",
		"--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeCouchDBOption, "--" + kmsSecretsDatabaseURLFlagName,
		"badURL",
	}
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "failed to ping couchDB")
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080", "--" + blocDomainFlagName, "domain",
		"--" + databaseTypeFlagName, databaseTypeMemOption,
		"--" + kmsSecretsDatabaseTypeFlagName, databaseTypeMemOption, "--" + tokenFlagName, "tk1",
		"--" + requestTokensFlagName, "token1=tk1", "--" + requestTokensFlagName, "token2=tk2",
		"--" + requestTokensFlagName, "token2=tk2=1", "--" + common.LogLevelFlagName, log.ParseString(log.ERROR),
		"--" + contextEnableRemoteFlagName, "true",
	}
	startCmd.SetArgs(args)

	err := startCmd.Execute()

	require.Nil(t, err)
	require.Equal(t, log.ERROR, log.GetLevel(""))
}

func TestHealthCheck(t *testing.T) {
	b := &httptest.ResponseRecorder{}
	healthCheckHandler(b, nil)

	require.Equal(t, http.StatusOK, b.Code)
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t, databaseTypeMemOption)

	defer unsetEnvVars(t)

	err := startCmd.Execute()
	require.NoError(t, err)
}

func TestCreateProviders(t *testing.T) {
	t.Run("test error from create new couchdb", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{dbParameters: &dbParameters{databaseType: databaseTypeCouchDBOption}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to ping couchDB: url can't be blank")
	})
	t.Run("test error from create new mysql", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{dbParameters: &dbParameters{databaseType: databaseTypeMYSQLDBOption}}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "DB URL for new mySQL DB provider can't be blank")
	})
	t.Run("test error from create new mongodb", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{dbParameters: &dbParameters{databaseType: databaseTypeMongoDBOption}}, nil)
		require.EqualError(t, err, "failed to create a new MongoDB client: error parsing uri: scheme must "+
			`be "mongodb" or "mongodb+srv"`)
	})
	t.Run("test error from create new kms secrets couchdb", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{
			dbParameters: &dbParameters{
				databaseType:           databaseTypeMemOption,
				kmsSecretsDatabaseType: databaseTypeCouchDBOption,
			},
		}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to ping couchDB: url can't be blank")
	})
	t.Run("test error from create new kms secrets mysql", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{
			dbParameters: &dbParameters{
				databaseType:           databaseTypeMemOption,
				kmsSecretsDatabaseType: databaseTypeMYSQLDBOption,
			},
		}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "DB URL for new mySQL DB provider can't be blank")
	})
	t.Run("test error from create new kms secrets mongodb", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{
			dbParameters: &dbParameters{
				databaseType:           databaseTypeMemOption,
				kmsSecretsDatabaseType: databaseTypeMongoDBOption,
			},
		}, nil)
		require.EqualError(t, err, "failed to create a new MongoDB client: error parsing uri: scheme must "+
			`be "mongodb" or "mongodb+srv"`)
	})
	t.Run("test invalid database type", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{dbParameters: &dbParameters{databaseType: "data1"}}, nil)
		require.EqualError(t, err, "data1 is not a valid database type. "+
			"run start --help to see the available options")
	})
	t.Run("test invalid kms secrets database type", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{
			dbParameters: &dbParameters{
				databaseType:           databaseTypeMemOption,
				kmsSecretsDatabaseType: "data1",
			},
		}, nil)
		require.EqualError(t, err, "data1 is not a valid KMS secrets database type. "+
			"run start --help to see the available options")
	})
}

func TestCreateKMS(t *testing.T) {
	t.Run("fail to open master key store", func(t *testing.T) {
		localKMS, err := createKMS(&ariesmockstorage.MockStoreProvider{FailNamespace: "masterkey"})

		require.Nil(t, localKMS)
		require.EqualError(t, err, "failed to open store for name space masterkey")
	})
	t.Run("fail to create master key service", func(t *testing.T) {
		masterKeyStore := ariesmockstorage.MockStore{
			Store: make(map[string]ariesmockstorage.DBEntry),
		}

		err := masterKeyStore.Put("masterkey", []byte(""))
		require.NoError(t, err)

		localKMS, err := createKMS(&ariesmockstorage.MockStoreProvider{Store: &masterKeyStore})
		require.EqualError(t, err, "masterKeyReader is empty")
		require.Nil(t, localKMS)
	})
}

func TestCreateVDRI(t *testing.T) {
	t.Run("test error from create new universal resolver vdr", func(t *testing.T) {
		v, err := createVDRI("wrong", &tls.Config{MinVersion: tls.VersionTLS12}, "", "")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdr")
		require.Nil(t, v)
	})

	t.Run("test error from create new universal resolver vdr", func(t *testing.T) {
		err := startEdgeService(&vcRestParameters{
			universalResolverURL: "wrong",
			dbParameters:         &dbParameters{databaseType: "mem", kmsSecretsDatabaseType: "mem"},
		}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new universal resolver vdr")
	})

	t.Run("test success", func(t *testing.T) {
		v, err := createVDRI("localhost:8083", &tls.Config{MinVersion: tls.VersionTLS12}, "", "")
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func TestAcceptedDIDs(t *testing.T) {
	t.Run("Test accepted DID methods", func(t *testing.T) {
		tests := []struct {
			method string
			result bool
		}{
			{
				method: didMethodVeres,
				result: true,
			},
			{
				method: didMethodSov,
				result: true,
			},
			{
				method: didMethodElement,
				result: true,
			},
			{
				method: "edge",
				result: false,
			},
			{
				method: "invalid",
				result: false,
			},
		}

		t.Parallel()

		for _, test := range tests {
			tc := test
			t.Run(tc.method, func(t *testing.T) {
				require.Equal(t, tc.result, acceptsDID(tc.method))
			})
		}
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t, databaseTypeMemOption)

	defer unsetEnvVars(t)
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func TestPrepareMasterKeyReader(t *testing.T) {
	t.Run("Unexpected error when trying to retrieve master key from store", func(t *testing.T) {
		reader, err := prepareMasterKeyReader(
			&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					ErrGet: errors.New("testError"),
				},
			})
		require.Equal(t, errors.New("testError"), err)
		require.Nil(t, reader)
	})
	t.Run("Error when putting newly generated master key into store", func(t *testing.T) {
		reader, err := prepareMasterKeyReader(
			&ariesmockstorage.MockStoreProvider{
				Store: &ariesmockstorage.MockStore{
					ErrGet: storage.ErrDataNotFound,
					ErrPut: errors.New("testError"),
				},
			})
		require.Equal(t, errors.New("testError"), err)
		require.Nil(t, reader)
	})
}

func TestValidateAuthorizationBearerToken(t *testing.T) {
	t.Run("test invalid token", func(t *testing.T) {
		header := make(map[string][]string)
		header["Authorization"] = []string{"Bearer tk1"}
		require.False(t, validateAuthorizationBearerToken(&httptest.ResponseRecorder{},
			&http.Request{Header: header}, "tk2"))
	})

	t.Run("test valid token", func(t *testing.T) {
		header := make(map[string][]string)
		header["Authorization"] = []string{"Bearer tk1"}
		require.True(t, validateAuthorizationBearerToken(&httptest.ResponseRecorder{},
			&http.Request{Header: header}, "tk1"))
	})
}

func TestContextEnableRemoteInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	setEnvVars(t, databaseTypeMemOption)

	defer unsetEnvVars(t)
	require.NoError(t, os.Setenv(contextEnableRemoteEnvKey, "not bool"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func setEnvVars(t *testing.T, databaseType string) {
	t.Helper()

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(blocDomainEnvKey, "domain")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, databaseType)
	require.NoError(t, err)

	err = os.Setenv(kmsSecretsDatabaseTypeEnvKey, databaseTypeMemOption)
	require.NoError(t, err)
}

func unsetEnvVars(t *testing.T) {
	t.Helper()

	err := os.Unsetenv(hostURLEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(blocDomainEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(databaseTypeEnvKey)
	require.NoError(t, err)

	err = os.Unsetenv(kmsSecretsDatabasePrefixEnvKey)
	require.NoError(t, err)
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	t.Helper()

	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}
