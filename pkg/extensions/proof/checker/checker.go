/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package checker

import (
	"encoding/hex"
	"fmt"

	"github.com/tidwall/gjson"
	"github.com/veraison/go-cose"

	"github.com/dellekappa/did-go/doc/ld/processor"
	"github.com/dellekappa/did-go/doc/ld/proof"
	"github.com/dellekappa/kcms-go/doc/jose"
	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	"github.com/dellekappa/kcms-go/doc/jose/jwk/jwksupport"
	"github.com/dellekappa/kcms-go/spi/kms"
	"github.com/dellekappa/vc-go/crypto-ext/pubkey"
	proofdesc "github.com/dellekappa/vc-go/proof"
	"github.com/dellekappa/vc-go/vermethod"

	"github.com/trustbloc/vcs/pkg/doc/vc/crypto"
)

type verificationMethodResolver interface {
	ResolveVerificationMethod(verificationMethod string, expectedProofIssuer string) (*vermethod.VerificationMethod, error)
}

type signatureVerifier interface {
	// SupportedKeyType checks if verifier supports given key.
	SupportedKeyType(keyType kms.KeyType) bool
	// Verify verifies the signature.
	Verify(sig, msg []byte, pub *pubkey.PublicKey) error
}

type signatureVerifierEx interface {
	// Verify verifies the signature.
	Verify(sig, msg []byte, pub *pubkey.PublicKey, proof *proof.Proof) error
}

type VerifyFunc func(signature, msg []byte, pubKey *pubkey.PublicKey) error

// Verifier verifies elliptic curve signatures.
type signatureVerifierWrapper struct {
	wrapped           signatureVerifier
	wrappedVerifyFunc VerifyFunc
}

func newSignatureVerifierWrapper(wrapped signatureVerifier,
	wrapperFunc func(verify VerifyFunc) VerifyFunc) signatureVerifier {
	return &signatureVerifierWrapper{
		wrapped:           wrapped,
		wrappedVerifyFunc: wrapperFunc(wrapped.Verify),
	}
}

// SupportedKeyType checks if verifier supports given key.
func (sv *signatureVerifierWrapper) SupportedKeyType(keyType kms.KeyType) bool {
	return sv.wrapped.SupportedKeyType(keyType)
}
func (sv *signatureVerifierWrapper) Verify(signature, msg []byte, pubKey *pubkey.PublicKey) error {
	return sv.wrappedVerifyFunc(signature, msg, pubKey)
}

type ldCheckDescriptor struct {
	proofDescriptor          proofdesc.LDProofDescriptor
	proofSignatureVerifierEx signatureVerifierEx
}

type jwtCheckDescriptor struct {
	proofDescriptor proofdesc.JWTProofDescriptor
}

type cwtCheckDescriptor struct {
	proofDescriptor proofdesc.JWTProofDescriptor
}

// nolint: gochecknoglobals
var possibleIssuerPath = []string{
	"vc.issuer.id",
	"vc.issuer",
	"issuer.id",
	"issuer",
	"iss",
}

// ProofCheckerBase basic implementation of proof checker.
type ProofCheckerBase struct {
	supportedLDProofs  []ldCheckDescriptor
	supportedJWTProofs []jwtCheckDescriptor
	supportedCWTProofs []cwtCheckDescriptor
	signatureVerifiers []signatureVerifier
}

// ProofChecker checks proofs of jd and jwt documents.
type ProofChecker struct {
	ProofCheckerBase

	verificationMethodResolver verificationMethodResolver
}

// Opt represent checker creation options.
type Opt func(c *ProofCheckerBase)

// WithLDProofTypes option to set supported ld proofs.
func WithLDProofTypes(proofDescs ...proofdesc.LDProofDescriptor) Opt {
	return func(c *ProofCheckerBase) {
		for _, proofDesc := range proofDescs {
			c.supportedLDProofs = append(c.supportedLDProofs, ldCheckDescriptor{
				proofDescriptor: proofDesc,
			})
		}
	}
}

// WithLDProofTypeEx option to set supported ld proofs.
func WithLDProofTypeEx(proofDesc proofdesc.LDProofDescriptor, proofSignatureVerifier signatureVerifierEx) Opt {
	return func(c *ProofCheckerBase) {
		c.supportedLDProofs = append(c.supportedLDProofs, ldCheckDescriptor{
			proofDescriptor:          proofDesc,
			proofSignatureVerifierEx: proofSignatureVerifier,
		})
	}
}

// WithJWTAlg option to set supported jwt algs.
func WithJWTAlg(proofDescs ...proofdesc.JWTProofDescriptor) Opt {
	return func(c *ProofCheckerBase) {
		for _, proofDesc := range proofDescs {
			c.supportedJWTProofs = append(c.supportedJWTProofs, jwtCheckDescriptor{
				proofDescriptor: proofDesc,
			})
		}
	}
}

// WithCWTAlg option to set supported jwt algs.
func WithCWTAlg(proofDescs ...proofdesc.JWTProofDescriptor) Opt {
	return func(c *ProofCheckerBase) {
		for _, proofDesc := range proofDescs {
			c.supportedCWTProofs = append(c.supportedCWTProofs, cwtCheckDescriptor{
				proofDescriptor: proofDesc,
			})
		}
	}
}

// WithSignatureVerifiers option to set signature verifiers.
func WithSignatureVerifiers(verifiers ...signatureVerifier) Opt {
	return func(c *ProofCheckerBase) {
		c.signatureVerifiers = append(c.signatureVerifiers, verifiers...)
	}
}

// New creates new proof checker.
func New(verificationMethodResolver verificationMethodResolver, opts ...Opt) *ProofChecker {
	c := &ProofChecker{
		verificationMethodResolver: verificationMethodResolver,
	}

	for _, opt := range opts {
		opt(&c.ProofCheckerBase)
	}

	return c
}

// CheckLDProof check ld proof.
func (c *ProofChecker) CheckLDProof(proof *proof.Proof, expectedProofIssuer string, msg, signature []byte) error {
	publicKeyID, err := proof.PublicKeyID()
	if err != nil {
		return fmt.Errorf("proof missing public key id: %w", err)
	}

	vm, err := c.verificationMethodResolver.ResolveVerificationMethod(publicKeyID, expectedProofIssuer)
	if err != nil {
		return fmt.Errorf("proof invalid public key id: %w", err)
	}

	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return err
	}

	pubKey, err := convertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), vm)
	if err != nil {
		return fmt.Errorf("%s proof check: %w", proof.Type, err)
	}

	if supportedProof.proofSignatureVerifierEx != nil {
		return supportedProof.proofSignatureVerifierEx.Verify(signature, msg, pubKey, proof)
	}

	verifier, err := c.getSignatureVerifier(pubKey.Type)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKey)
}

// GetLDPCanonicalDocument will return normalized/canonical version of the document.
func (c *ProofCheckerBase) GetLDPCanonicalDocument(proof *proof.Proof,
	doc map[string]interface{}, opts ...processor.Opts) ([]byte, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return nil, err
	}

	return supportedProof.proofDescriptor.GetCanonicalDocument(doc, opts...)
}

// GetLDPDigest returns document digest.
func (c *ProofCheckerBase) GetLDPDigest(proof *proof.Proof, doc []byte) ([]byte, error) {
	supportedProof, err := c.getSupportedProof(proof.Type)
	if err != nil {
		return nil, err
	}

	return supportedProof.proofDescriptor.GetDigest(doc), nil
}

// CheckJWTProof check jwt proof.
func (c *ProofChecker) CheckJWTProof(headers jose.Headers, expectedProofIssuer string, msg, signature []byte) error {
	key, jwkOk := headers.JWK()

	keyID, kidOk := headers.KeyID()
	if !kidOk && !jwkOk {
		return fmt.Errorf("missed kid or jwk in jwt header")
	}
	if kidOk && jwkOk {
		return fmt.Errorf("both kid and jwk in jwt header")
	}

	alg, ok := headers.Algorithm()
	if !ok {
		return fmt.Errorf("missed alg in jwt header")
	}

	supportedProof, err := c.getSupportedProofByAlg(alg)
	if err != nil {
		return err
	}

	var vm *vermethod.VerificationMethod
	if kidOk {
		vm, err = c.verificationMethodResolver.ResolveVerificationMethod(keyID, expectedProofIssuer)
		if err != nil {
			return fmt.Errorf("invalid public key id: %w", err)
		}
	} else {
		keyBytes, err := key.PublicKeyBytes() //nolint:govet
		if err != nil {
			return fmt.Errorf("invalid public jwk: %w", err)
		}
		vm = &vermethod.VerificationMethod{
			Type:  crypto.JSONWebKey2020,
			Value: keyBytes,
			JWK:   key,
		}
	}

	pubKey, err := convertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), vm) //nolint:govet
	if err != nil {
		return fmt.Errorf("jwt with alg %s check: %w", alg, err)
	}

	verifier, err := c.getSignatureVerifier(pubKey.Type)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKey)
}

func (c *ProofChecker) checkCWTProofByKeyID(
	checkCWTRequest CheckCWTProofRequest,
	expectedProofIssuer string,
	msg []byte,
	signature []byte,
) error {
	vm, err := c.verificationMethodResolver.ResolveVerificationMethod(checkCWTRequest.KeyID, expectedProofIssuer)
	if err != nil {
		return fmt.Errorf("invalid public key id: %w", err)
	}

	supportedProof, err := c.getSupportedCWTProofByAlg(checkCWTRequest.Algo)
	if err != nil {
		return err
	}

	pubKey, err := convertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), vm)
	if err != nil {
		return fmt.Errorf("cwt with alg %s check: %w", checkCWTRequest.Algo, err)
	}

	verifier, err := c.getSignatureVerifier(pubKey.Type)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKey)
}

func (c *ProofChecker) checkCWTProofByCOSEKey(
	checkCWTRequest CheckCWTProofRequest,
	expectedProofIssuer string,
	msg []byte,
	signature []byte,
) error {
	if expectedProofIssuer != "" {
		return fmt.Errorf("checking expected issuer is not supported by CWT for COSE_KEY")
	}

	keyMaterialBytes, err := hex.DecodeString(checkCWTRequest.KeyMaterial)
	if err != nil {
		return fmt.Errorf("failed to decode key material: %w", err)
	}

	var targetKey cose.Key
	if err = targetKey.UnmarshalCBOR(keyMaterialBytes); err != nil {
		return fmt.Errorf("failed to unmarshal key material: %w", err)
	}

	pubKey, err := targetKey.PublicKey()
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}

	jwkWrapper, err := jwksupport.JWKFromKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to create JWK from key: %w", err)
	}

	kmsKeyType, err := jwkWrapper.KeyType()
	if err != nil {
		return fmt.Errorf("failed to get key type: %w", err)
	}

	supportedProof, err := c.getSupportedCWTProofByAlg(checkCWTRequest.Algo)
	if err != nil {
		return err
	}

	pubKeyFinal, err := convertToPublicKey(
		supportedProof.proofDescriptor.SupportedVerificationMethods(), &vermethod.VerificationMethod{
			Type:  "JsonWebKey2020",
			Value: nil,
			JWK:   jwkWrapper,
		})
	if err != nil {
		return fmt.Errorf("convertToPublicKey. cwt with alg %s check: %w", checkCWTRequest.Algo, err)
	}

	verifier, err := c.getSignatureVerifier(kmsKeyType)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKeyFinal)
}

// CheckCWTProof check cwt proof.
func (c *ProofChecker) CheckCWTProof(
	checkCWTRequest CheckCWTProofRequest,
	expectedProofIssuer string,
	msg []byte,
	signature []byte,
) error {
	if checkCWTRequest.KeyID == "" && checkCWTRequest.KeyMaterial == "" {
		return fmt.Errorf("missed kid and COSE_Key in cwt header")
	}

	if checkCWTRequest.Algo == 0 {
		return fmt.Errorf("missed alg in cwt header")
	}

	if checkCWTRequest.KeyID != "" {
		return c.checkCWTProofByKeyID(
			checkCWTRequest,
			expectedProofIssuer,
			msg,
			signature,
		)
	}

	return c.checkCWTProofByCOSEKey(
		checkCWTRequest,
		expectedProofIssuer,
		msg,
		signature,
	)
}

// FindIssuer finds issuer in payload.
func (c *ProofChecker) FindIssuer(payload []byte) string {
	parsed := gjson.ParseBytes(payload)

	for _, p := range possibleIssuerPath {
		if str := parsed.Get(p).Str; str != "" {
			return str
		}
	}

	return ""
}

func (c *ProofChecker) WithSignatureVerificationWrapping(wrapper func(VerifyFunc) VerifyFunc) *ProofChecker {
	base := &c.ProofCheckerBase
	return &ProofChecker{
		ProofCheckerBase:           *base.WithSignatureVerificationWrapping(wrapper),
		verificationMethodResolver: c.verificationMethodResolver,
	}
}

func wrapSignatureVerifiers(verifiers []signatureVerifier,
	wrapper func(verify VerifyFunc) VerifyFunc) []signatureVerifier {
	result := make([]signatureVerifier, len(verifiers))
	for i := range verifiers {
		result[i] = newSignatureVerifierWrapper(verifiers[i], wrapper)
	}
	return result
}

func convertToPublicKey(
	supportedMethods []proofdesc.SupportedVerificationMethod,
	vm *vermethod.VerificationMethod,
) (*pubkey.PublicKey, error) {
	for _, supported := range supportedMethods {
		if supported.VerificationMethodType != vm.Type {
			continue
		}

		if vm.JWK == nil && supported.RequireJWK {
			continue
		}

		if vm.JWK != nil && (supported.JWKKeyType != vm.JWK.Kty || supported.JWKCurve != vm.JWK.Crv) {
			continue
		}

		return createPublicKey(vm, supported.KMSKeyType), nil
	}

	jwkKty := ""
	jwkCrv := ""

	if vm.JWK != nil {
		jwkKty = vm.JWK.Kty
		jwkCrv = vm.JWK.Crv
	}

	return nil, fmt.Errorf("can't verifiy with %q verification method (jwk type %q, jwk curve %q)",
		vm.Type, jwkKty, jwkCrv)
}

func createPublicKey(vm *vermethod.VerificationMethod, keyType kms.KeyType) *pubkey.PublicKey {
	if vm.JWK != nil {
		return &pubkey.PublicKey{Type: keyType, JWK: vm.JWK}
	}

	return &pubkey.PublicKey{Type: keyType, BytesKey: &pubkey.BytesKey{Bytes: vm.Value}}
}

func (c *ProofCheckerBase) getSupportedProof(proofType string) (ldCheckDescriptor, error) {
	for _, supported := range c.supportedLDProofs {
		if supported.proofDescriptor.ProofType() == proofType {
			return supported, nil
		}
	}

	return ldCheckDescriptor{}, fmt.Errorf("unsupported proof type: %s", proofType)
}

func (c *ProofCheckerBase) getSupportedProofByAlg(jwtAlg string) (jwtCheckDescriptor, error) {
	for _, supported := range c.supportedJWTProofs {
		if supported.proofDescriptor.JWTAlgorithm() == jwtAlg {
			return supported, nil
		}
	}

	return jwtCheckDescriptor{}, fmt.Errorf("unsupported jwt alg: %s", jwtAlg)
}

func (c *ProofCheckerBase) getSupportedCWTProofByAlg(cwtAlg cose.Algorithm) (cwtCheckDescriptor, error) {
	for _, supported := range c.supportedCWTProofs {
		if supported.proofDescriptor.CWTAlgorithm() == cwtAlg {
			return supported, nil
		}
	}

	return cwtCheckDescriptor{}, fmt.Errorf("unsupported cwt alg: %s", cwtAlg)
}

func (c *ProofCheckerBase) getSignatureVerifier(keyType kms.KeyType) (signatureVerifier, error) {
	for _, verifier := range c.signatureVerifiers {
		if verifier.SupportedKeyType(keyType) {
			return verifier, nil
		}
	}

	return nil, fmt.Errorf("no vefiers with supported key type %s", keyType)
}

func (c *ProofCheckerBase) WithSignatureVerificationWrapping(
	wrapper func(verify VerifyFunc) VerifyFunc) *ProofCheckerBase {
	return &ProofCheckerBase{
		supportedLDProofs:  c.supportedLDProofs,
		supportedJWTProofs: c.supportedJWTProofs,
		supportedCWTProofs: c.supportedCWTProofs,
		signatureVerifiers: wrapSignatureVerifiers(c.signatureVerifiers, wrapper),
	}
}

// EmbeddedVMProofChecker is a proof  checker with embedded verification method.
type EmbeddedVMProofChecker struct {
	ProofCheckerBase
	vm *vermethod.VerificationMethod
}

// CheckJWTProof check jwt proof.
func (c *EmbeddedVMProofChecker) CheckJWTProof(headers jose.Headers, _ string, msg, signature []byte) error {
	alg, ok := headers.Algorithm()
	if !ok {
		return fmt.Errorf("missed alg in jwt header")
	}

	supportedProof, err := c.getSupportedProofByAlg(alg)
	if err != nil {
		return err
	}

	pubKey, err := convertToPublicKey(supportedProof.proofDescriptor.SupportedVerificationMethods(), c.vm)
	if err != nil {
		return fmt.Errorf("jwt with alg %s check: %w", alg, err)
	}

	verifier, err := c.getSignatureVerifier(pubKey.Type)
	if err != nil {
		return err
	}

	return verifier.Verify(signature, msg, pubKey)
}

func (c *EmbeddedVMProofChecker) WithSignatureVerificationWrapping(
	wrapper func(VerifyFunc) VerifyFunc) *EmbeddedVMProofChecker {
	base := &c.ProofCheckerBase
	return &EmbeddedVMProofChecker{
		ProofCheckerBase: *base.WithSignatureVerificationWrapping(wrapper),
		vm:               c.vm,
	}
}

// NewEmbeddedJWKProofChecker return new EmbeddedVMProofChecker with embedded jwk.
func NewEmbeddedJWKProofChecker(jwk *jwk.JWK, opts ...Opt) *EmbeddedVMProofChecker {
	return NewEmbeddedVMProofChecker(&vermethod.VerificationMethod{Type: "JsonWebKey2020", JWK: jwk}, opts...)
}

// NewEmbeddedVMProofChecker return new EmbeddedVMProofChecker.
func NewEmbeddedVMProofChecker(vm *vermethod.VerificationMethod, opts ...Opt) *EmbeddedVMProofChecker {
	c := &EmbeddedVMProofChecker{
		vm: vm,
	}

	for _, opt := range opts {
		opt(&c.ProofCheckerBase)
	}

	return c
}
