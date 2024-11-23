/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package issuecredential_test

import (
	"context"
	"testing"
	"time"

	util "github.com/dellekappa/did-go/doc/util/time"
	"github.com/dellekappa/vc-go/verifiable"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/vcs/pkg/service/issuecredential"
)

func TestComposer(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		srv := issuecredential.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			Types: []string{"VerifiableCredential"},
			Context: []string{
				"https://www.w3.org/2018/credentials/v1",
			},
			Subject: []verifiable.Subject{{ID: "xxx:yyy"}},
		}, verifiable.CustomFields{})
		assert.NoError(t, err)

		expectedExpiration := time.Now().UTC()

		resp, err := srv.Compose(
			context.TODO(),
			cred,
			&issuecredential.PrepareCredentialsRequest{
				TxID:       "some-awesome-id",
				IssuerDID:  "did:example:123",
				SubjectDID: "some-awesome-did",
				CredentialConfiguration: &issuecredential.TxCredentialConfiguration{
					CredentialComposeConfiguration: &issuecredential.CredentialComposeConfiguration{
						IDTemplate:         "hardcoded:{{.TxID}}:suffix",
						OverrideIssuer:     true,
						OverrideSubjectDID: true,
					},
					CredentialExpiresAt: &expectedExpiration,
				},
			},
		)

		assert.NotNil(t, resp.Contents().Issued)
		assert.NotNil(t, resp.Contents().Expired)

		assert.NoError(t, err)
		assert.NotNil(t, resp)

		credJSON, err := resp.MarshalAsJSONLD()
		assert.NoError(t, err)

		parsedCred, err := verifiable.ParseCredential(credJSON,
			verifiable.WithCredDisableValidation(),
			verifiable.WithDisabledProofCheck(),
		)
		assert.NoError(t, err)

		assert.EqualValues(t, "hardcoded:some-awesome-id:suffix", resp.Contents().ID)
		assert.EqualValues(t, "did:example:123", resp.Contents().Issuer.ID)
		assert.EqualValues(t, "some-awesome-did", resp.Contents().Subject[0].ID)
		assert.EqualValues(t, expectedExpiration, parsedCred.Contents().Expired.Time)
		assert.NotNil(t, expectedExpiration, parsedCred.Contents().Issued)
	})

	t.Run("success - V2", func(t *testing.T) {
		srv := issuecredential.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			Types: []string{"VerifiableCredential"},
			Context: []string{
				verifiable.V2ContextURI,
			},
			Subject: []verifiable.Subject{{ID: "xxx:yyy"}},
		}, verifiable.CustomFields{})
		require.NoError(t, err)

		expectedExpiration := time.Now().UTC()

		resp, err := srv.Compose(
			context.TODO(),
			cred,
			&issuecredential.PrepareCredentialsRequest{
				TxID:       "some-awesome-id",
				IssuerDID:  "did:example:123",
				SubjectDID: "some-awesome-did",
				CredentialConfiguration: &issuecredential.TxCredentialConfiguration{
					CredentialComposeConfiguration: &issuecredential.CredentialComposeConfiguration{
						IDTemplate:         "hardcoded:{{.TxID}}:suffix",
						OverrideIssuer:     true,
						OverrideSubjectDID: true,
					},
					CredentialExpiresAt: &expectedExpiration,
				},
			},
		)

		require.NotNil(t, resp.Contents().Issued)
		require.NotNil(t, resp.Contents().Expired)

		require.NoError(t, err)
		require.NotNil(t, resp)

		credJSON, err := resp.MarshalAsJSONLD()
		require.NoError(t, err)

		parsedCred, err := verifiable.ParseCredential(credJSON,
			verifiable.WithCredDisableValidation(),
			verifiable.WithDisabledProofCheck(),
		)
		require.NoError(t, err)

		require.EqualValues(t, "hardcoded:some-awesome-id:suffix", resp.Contents().ID)
		require.EqualValues(t, "did:example:123", resp.Contents().Issuer.ID)
		require.EqualValues(t, "some-awesome-did", resp.Contents().Subject[0].ID)
		require.EqualValues(t, expectedExpiration, parsedCred.Contents().Expired.Time)
		require.NotEmpty(t, parsedCred.CustomField("validFrom"))
		require.NotEmpty(t, parsedCred.CustomField("validUntil"))
	})

	t.Run("success with prev-id", func(t *testing.T) {
		srv := issuecredential.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{
			ID:      "some-id",
			Expired: util.NewTime(time.Now()),
			Issuer: &verifiable.Issuer{
				ID: "did:example:123",
				CustomFields: map[string]interface{}{
					"key":  "value",
					"name": "issuer",
				},
			},
			Subject: []verifiable.Subject{{ID: "xxx:yyy"}},
		}, verifiable.CustomFields{})
		assert.NoError(t, err)

		resp, err := srv.Compose(
			context.TODO(),
			cred,
			&issuecredential.PrepareCredentialsRequest{
				TxID:       "some-awesome-id",
				IssuerDID:  "did:example:123",
				SubjectDID: "some-awesome-did",
				CredentialConfiguration: &issuecredential.TxCredentialConfiguration{
					CredentialComposeConfiguration: &issuecredential.CredentialComposeConfiguration{
						IDTemplate:         "{{.CredentialID}}:suffix",
						OverrideIssuer:     true,
						OverrideSubjectDID: true,
					},
					CredentialExpiresAt: lo.ToPtr(time.Now()),
				},
			},
		)

		assert.NoError(t, err)
		assert.NotNil(t, resp)

		assert.EqualValues(t, "some-id:suffix", resp.Contents().ID)
		assert.EqualValues(t, "did:example:123", resp.Contents().Issuer.ID)
		assert.EqualValues(t, "value", resp.Contents().Issuer.CustomFields["key"])
		assert.EqualValues(t, "issuer", resp.Contents().Issuer.CustomFields["name"])

		assert.EqualValues(t, "some-awesome-did", resp.Contents().Subject[0].ID)
	})

	t.Run("invalid template", func(t *testing.T) {
		srv := issuecredential.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{}, verifiable.CustomFields{})
		assert.NoError(t, err)

		resp, err := srv.Compose(
			context.TODO(),
			cred,
			&issuecredential.PrepareCredentialsRequest{
				TxID:       "some-awesome-id",
				IssuerDID:  "did:example:123",
				SubjectDID: "some-awesome-did",
				CredentialConfiguration: &issuecredential.TxCredentialConfiguration{
					CredentialComposeConfiguration: &issuecredential.CredentialComposeConfiguration{
						IDTemplate:         "hardcoded:{{.NotExistingValue.$x}}:suffix",
						OverrideIssuer:     true,
						OverrideSubjectDID: true,
					},
					CredentialExpiresAt: lo.ToPtr(time.Now()),
				},
			},
		)

		assert.ErrorContains(t, err, "bad character")
		assert.Nil(t, resp)
	})

	t.Run("missing compose", func(t *testing.T) {
		srv := issuecredential.NewCredentialComposer()

		cred, err := verifiable.CreateCredential(verifiable.CredentialContents{}, verifiable.CustomFields{})
		assert.NoError(t, err)

		resp, err := srv.Compose(context.TODO(), cred, nil)
		assert.Equal(t, cred, resp)
		assert.NoError(t, err)
	})
}
