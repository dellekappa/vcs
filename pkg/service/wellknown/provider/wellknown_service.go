/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//go:generate mockgen -destination wellknown_service_mocks_test.go -package provider -source=wellknown_service.go -mock_names kmsRegistry=MockKMSRegistry,cryptoJWTSigner=MockCryptoJWTSigner

package provider

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	josejwt "github.com/go-jose/go-jose/v3/jwt"
	"github.com/samber/lo"

	"github.com/trustbloc/vc-go/jwt"

	"github.com/trustbloc/vcs/pkg/doc/vc"
	"github.com/trustbloc/vcs/pkg/kms"
	profileapi "github.com/trustbloc/vcs/pkg/profile"
	"github.com/trustbloc/vcs/pkg/restapi/v1/common"
	"github.com/trustbloc/vcs/pkg/restapi/v1/issuer"
)

type kmsRegistry interface {
	GetKeyManager(config *kms.Config) (kms.VCSKeyManager, error)
}

type cryptoJWTSigner interface {
	NewJWTSigned(claims interface{}, signerData *vc.Signer) (string, error)
}

// JWTWellKnownOpenIDIssuerConfigurationClaims is JWT Claims extension by WellKnownOpenIDIssuerConfiguration.
type JWTWellKnownOpenIDIssuerConfigurationClaims struct {
	*jwt.Claims
	*issuer.WellKnownOpenIDIssuerConfiguration
}

type Config struct {
	ExternalHostURL string
	KMSRegistry     kmsRegistry
	CryptoJWTSigner cryptoJWTSigner
}

type Service struct {
	externalHostURL string
	kmsRegistry     kmsRegistry
	cryptoJWTSigner cryptoJWTSigner
}

func NewService(config *Config) *Service {
	return &Service{
		externalHostURL: config.ExternalHostURL,
		kmsRegistry:     config.KMSRegistry,
		cryptoJWTSigner: config.CryptoJWTSigner,
	}
}

func (s *Service) GetOpenIDConfig(
	issuerProfile *profileapi.Issuer) (*issuer.WellKnownOpenIDConfiguration, error) {

	issuerMetadata := s.getOpenIDIssuerConfig(issuerProfile)

	metadata := &issuer.WellKnownOpenIDConfiguration{
		AuthorizationEndpoint:             issuerMetadata.AuthorizationEndpoint,
		BackchannelLogoutSessionRequired:  lo.ToPtr(true),
		BackchannelLogoutSupported:        lo.ToPtr(true),
		ClaimsParameterSupported:          lo.ToPtr(true),
		CodeChallengeMethodsSupported:     lo.ToPtr([]string{"S256"}),
		CredentialEndpoint:                issuerMetadata.CredentialEndpoint,
		EndSessionEndpoint:                lo.ToPtr("https://fake.idp/session"),
		FrontchannelLogoutSessionRequired: lo.ToPtr(true),
		FrontchannelLogoutSupported:       lo.ToPtr(true),
		GrantTypesSupported:               issuerMetadata.GrantTypesSupported,
		IdTokenSigningAlgValuesSupported: lo.ToPtr([]string{
			"RS256",
			"RS384",
			"RS512",
			"ES256",
			"ES384",
			"ES512",
			"PS256",
			"PS384",
			"PS512",
			"HS256",
			"HS384",
			"HS512",
		}),
		IntrospectionEndpoint:              lo.ToPtr("https://fake.idp/introspection"),
		Issuer:                             issuerMetadata.CredentialIssuer,
		JwksUri:                            lo.ToPtr("https://fake.idp/jwks"),
		PushedAuthorizationRequestEndpoint: lo.ToPtr("https://fake.idp/par"),
		RegistrationEndpoint:               issuerMetadata.RegistrationEndpoint,
		RequestObjectSigningAlgValuesSupported: lo.ToPtr([]string{
			"RS256",
			"RS384",
			"RS512",
			"ES256",
			"ES384",
			"ES512",
			"PS256",
			"PS384",
			"PS512",
			"HS256",
			"HS384",
			"HS512",
		}),
		RequestParameterSupported:     lo.ToPtr(true),
		RequestUriParameterSupported:  lo.ToPtr(true),
		RequireRequestUriRegistration: lo.ToPtr(false),
		ResponseModesSupported: lo.ToPtr([]string{
			"query",
			"fragment",
			"form_post",
		}),
		ResponseTypesSupported: issuerMetadata.ResponseTypesSupported,
		ScopesSupported:        issuerMetadata.ScopesSupported,
		SubjectTypesSupported: lo.ToPtr([]string{
			"public",
			"pairwise",
		}),
		TokenEndpoint: issuerMetadata.TokenEndpoint,
		//TokenEndpointAuthMethodsSupported: issuerMetadata.TokenEndpointAuthMethodsSupported,
		TokenEndpointAuthMethodsSupported: lo.ToPtr([]string{"public"}),
		UserinfoEndpoint:                  lo.ToPtr("https://fake.idp/userinfo"),
		UserinfoSigningAlgValuesSupported: lo.ToPtr([]string{
			"RS256",
			"RS384",
			"RS512",
			"ES256",
			"ES384",
			"ES512",
			"PS256",
			"PS384",
			"PS512",
			"HS256",
			"HS384",
			"HS512",
		}),
	}

	return metadata, nil
}

// GetOpenIDCredentialIssuerConfig returns issuer.WellKnownOpenIDIssuerConfiguration object, and
// it's JWT signed representation, if this feature is enabled for specific profile.
//
// # Note, that if the Credential Issuer wants to enforce use of signed metadata,
// it omits the respective metadata parameters from the unsigned part of the Credential Issuer metadata.
// In this case, HTTP response should be:
//
//	{
//	 "signed_metadata": "jwt_representation"
//	}
//
// Used for creating GET .well-known/openid-credential-issuer VCS IDP response.
func (s *Service) GetOpenIDCredentialIssuerConfig(
	issuerProfile *profileapi.Issuer) (*issuer.WellKnownOpenIDIssuerConfiguration, string, error) {
	var (
		jwtSignedIssuerMetadata string
		err                     error
	)

	issuerMetadata := s.getOpenIDIssuerConfig(issuerProfile)

	if issuerProfile.OIDCConfig != nil && issuerProfile.OIDCConfig.SignedIssuerMetadataSupported {
		jwtSignedIssuerMetadata, err = s.signIssuerMetadata(issuerProfile, issuerMetadata)
		if err != nil {
			return nil, "", err
		}
	}

	return issuerMetadata, jwtSignedIssuerMetadata, nil
}

func (s *Service) getOpenIDIssuerConfig(issuerProfile *profileapi.Issuer) *issuer.WellKnownOpenIDIssuerConfiguration {
	// TODO: add support of internationalization and Accept-Language Header for this function.
	// Spec: https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-wg-draft.html#section-11.2.2
	// For now, the following option from the spec supported:
	// - ignore the Accept-Language Header and send all supported languages or any chosen subset.
	host := s.externalHostURL
	if !strings.HasSuffix(host, "/") {
		host += "/"
	}

	credentialsConfigurationSupported := s.buildCredentialConfigurationsSupported(issuerProfile)

	//issuerURL, _ := url.JoinPath(s.externalHostURL, "issuer", issuerProfile.ID, issuerProfile.Version)
	issuerURL, _ := url.JoinPath(s.externalHostURL, "oidc", "idp", issuerProfile.ID, issuerProfile.Version)

	//credentialIssuerMetadataDisplay := s.buildCredentialIssuerMetadataDisplay(
	//	issuerProfile.Name,
	//	issuerProfile.URL,
	//	issuerProfile.CredentialMetaData.Display,
	//)

	final := &issuer.WellKnownOpenIDIssuerConfiguration{
		CredentialIssuer:               &issuerURL,
		AuthorizationEndpoint:          lo.ToPtr(fmt.Sprintf("%soidc/authorize", host)),
		CredentialEndpoint:             lo.ToPtr(fmt.Sprintf("%soidc/credential", host)),
		BatchCredentialEndpoint:        lo.ToPtr(fmt.Sprintf("%soidc/batch_credential", host)),
		DeferredCredentialEndpoint:     lo.ToPtr(fmt.Sprintf("%soidc/deferred_credential", host)),
		CredentialResponseEncryption:   nil,
		CredentialIdentifiersSupported: nil,
		SignedMetadata:                 nil,
		//Display:                           lo.ToPtr(credentialIssuerMetadataDisplay),
		CredentialConfigurationsSupported: credentialsConfigurationSupported,

		NotificationEndpoint:   lo.ToPtr(fmt.Sprintf("%soidc/notification", host)),
		TokenEndpoint:          lo.ToPtr(fmt.Sprintf("%soidc/token", host)),
		ResponseTypesSupported: lo.ToPtr([]string{"code"}),
	}

	if issuerProfile.OIDCConfig != nil {
		if issuerProfile.OIDCConfig.EnableDynamicClientRegistration {
			regURL, _ := url.JoinPath(host, "oidc", issuerProfile.ID, issuerProfile.Version, "register")

			final.RegistrationEndpoint = lo.ToPtr(regURL)
		}

		final.TokenEndpointAuthMethodsSupported = lo.ToPtr(issuerProfile.OIDCConfig.TokenEndpointAuthMethodsSupported)
		final.ScopesSupported = lo.ToPtr(issuerProfile.OIDCConfig.ScopesSupported)
		final.GrantTypesSupported = lo.ToPtr(issuerProfile.OIDCConfig.GrantTypesSupported)
		final.PreAuthorizedGrantAnonymousAccessSupported =
			lo.ToPtr(issuerProfile.OIDCConfig.PreAuthorizedGrantAnonymousAccessSupported)
	}

	return final
}

func (s *Service) signIssuerMetadata(
	profile *profileapi.Issuer,
	meta *issuer.WellKnownOpenIDIssuerConfiguration,
) (string, error) {
	keyManager, err := s.kmsRegistry.GetKeyManager(profile.KMSConfig)
	if err != nil {
		return "", fmt.Errorf("get kms: %w", err)
	}

	signerData := &vc.Signer{
		KeyType:       profile.VCConfig.KeyType,
		KMSKeyID:      profile.SigningDID.KMSKeyID,
		KMS:           keyManager,
		SignatureType: profile.VCConfig.SigningAlgorithm,
		Creator:       profile.SigningDID.Creator,
	}

	claims := &JWTWellKnownOpenIDIssuerConfigurationClaims{
		Claims: &jwt.Claims{
			Issuer:   profile.SigningDID.DID,
			Subject:  profile.SigningDID.DID,
			IssuedAt: josejwt.NewNumericDate(time.Now()),
		},
		WellKnownOpenIDIssuerConfiguration: meta,
	}

	signedIssuerMetadata, err := s.cryptoJWTSigner.NewJWTSigned(claims, signerData)
	if err != nil {
		return "", fmt.Errorf("sign issuer metadata: %w", err)
	}

	return signedIssuerMetadata, nil
}

func (s *Service) buildCredentialIssuerMetadataDisplay(
	issuerProfileName, issuerProfileURL string,
	issuerProfileDisplay []*profileapi.CredentialDisplay,
) []issuer.CredentialDisplay {
	var display []issuer.CredentialDisplay
	if issuerProfileDisplay != nil {
		display = make([]issuer.CredentialDisplay, 0, len(issuerProfileDisplay))

		for _, d := range issuerProfileDisplay {
			credentialDisplay := issuer.CredentialDisplay{
				BackgroundColor: lo.ToPtr(d.BackgroundColor),
				Locale:          lo.ToPtr(d.Locale),
				Name:            lo.ToPtr(d.Name),
				TextColor:       lo.ToPtr(d.TextColor),
				Url:             lo.ToPtr(d.URL),
			}

			if d.Logo != nil {
				credentialDisplay.Logo = &issuer.Logo{
					AltText: lo.ToPtr(d.Logo.AlternativeText),
					Uri:     d.Logo.URI,
				}
			}

			display = append(display, credentialDisplay)
		}
	} else {
		display = []issuer.CredentialDisplay{
			{
				Locale: lo.ToPtr("en-US"),
				Name:   lo.ToPtr(issuerProfileName),
				Url:    lo.ToPtr(issuerProfileURL),
			},
		}
	}

	return display
}

func (s *Service) buildCredentialConfigurationsSupported(
	issuerProfile *profileapi.Issuer,
) *issuer.WellKnownOpenIDIssuerConfiguration_CredentialConfigurationsSupported {
	credentialsConfigurationSupported := &issuer.WellKnownOpenIDIssuerConfiguration_CredentialConfigurationsSupported{}

	var credentialConfSupported map[string]*profileapi.CredentialsConfigurationSupported
	if issuerProfile.CredentialMetaData != nil {
		credentialConfSupported = issuerProfile.CredentialMetaData.CredentialsConfigurationSupported
	}

	for credentialConfigurationID, credentialSupported := range credentialConfSupported {
		var cryptographicBindingMethodsSupported, signingAlgValuesSupported []string

		if issuerProfile.VCConfig != nil {
			cryptographicBindingMethodsSupported = []string{string(issuerProfile.VCConfig.DIDMethod)}
			signingAlgValuesSupported = []string{string(issuerProfile.VCConfig.SigningAlgorithm)}
			//signingAlgValuesSupported = []string{string(issuerProfile.VCConfig.KeyType)}
		}

		display := s.buildCredentialConfigurationsSupportedDisplay(credentialSupported.Display)
		credentialDefinition := s.buildCredentialDefinition(credentialSupported.CredentialDefinition)

		proofTypeSupported := &issuer.CredentialConfigurationsSupported_ProofTypesSupported{
			AdditionalProperties: map[string]issuer.ProofTypeSupported{
				"cwt": {
					ProofSigningAlgValuesSupported: []string{string(issuerProfile.VCConfig.SigningAlgorithm)},
					//ProofSigningAlgValuesSupported: []string{string(issuerProfile.VCConfig.KeyType)},
				},
				"jwt": {
					ProofSigningAlgValuesSupported: []string{string(issuerProfile.VCConfig.SigningAlgorithm)},
					//ProofSigningAlgValuesSupported: []string{string(issuerProfile.VCConfig.KeyType)},
				},
			},
		}

		c := issuer.CredentialConfigurationsSupported{
			Claims:                               lo.ToPtr(credentialSupported.Claims),
			CredentialDefinition:                 credentialDefinition,
			CryptographicBindingMethodsSupported: lo.ToPtr(cryptographicBindingMethodsSupported),
			CredentialSigningAlgValuesSupported:  lo.ToPtr(signingAlgValuesSupported),
			Display:                              lo.ToPtr(display),
			Doctype:                              lo.EmptyableToPtr(credentialSupported.Doctype),
			Format:                               string(credentialSupported.Format),
			Order:                                lo.ToPtr(credentialSupported.Order),
			ProofTypesSupported:                  proofTypeSupported,
			Scope:                                lo.EmptyableToPtr(credentialSupported.Scope),
			Vct:                                  lo.EmptyableToPtr(credentialSupported.Vct),
		}

		//if c.Format == "mso_mdoc" {
		//	c.IsoCredentialSigningAlgorithmsSupported = []int{-7}
		//	c.IsoCredentialCurvesSupported = []int{1}
		//	c.Policy = &issuer.CredentialPolicy{
		//		OneTimeUse: true,
		//		BatchSize:  lo.ToPtr(50),
		//	}
		//}

		credentialsConfigurationSupported.Set(credentialConfigurationID, c)
	}

	return credentialsConfigurationSupported
}

func (s *Service) buildCredentialDefinition(
	issuerCredentialDefinition *profileapi.CredentialDefinition,
) *common.CredentialDefinition {
	if issuerCredentialDefinition == nil {
		return nil
	}
	credentialSubject := make(map[string]interface{}, len(issuerCredentialDefinition.CredentialSubject))

	for k, v := range issuerCredentialDefinition.CredentialSubject {
		credentialSubject[k] = v
	}

	return &common.CredentialDefinition{
		Context:           lo.ToPtr(issuerCredentialDefinition.Context),
		CredentialSubject: lo.ToPtr(credentialSubject),
		Type:              issuerCredentialDefinition.Type,
	}
}

func (s *Service) buildCredentialConfigurationsSupportedDisplay(
	credentialSupportedDisplay []*profileapi.CredentialDisplay,
) []issuer.CredentialDisplay {
	credentialConfigurationsSupportedDisplay := make([]issuer.CredentialDisplay, 0, len(credentialSupportedDisplay))

	for _, display := range credentialSupportedDisplay {
		var logo *issuer.Logo
		if display.Logo != nil {
			logo = &issuer.Logo{
				AltText: lo.ToPtr(display.Logo.AlternativeText),
				Uri:     display.Logo.URI,
				//Url:     display.Logo.URL,
			}
		}

		credentialDisplay := issuer.CredentialDisplay{
			BackgroundColor: lo.EmptyableToPtr(display.BackgroundColor),
			Locale:          lo.ToPtr(display.Locale),
			Logo:            logo,
			Name:            lo.ToPtr(display.Name),
			TextColor:       lo.EmptyableToPtr(display.TextColor),
			Url:             lo.EmptyableToPtr(display.URL),
		}

		credentialConfigurationsSupportedDisplay = append(credentialConfigurationsSupportedDisplay, credentialDisplay)
	}

	return credentialConfigurationsSupportedDisplay
}
