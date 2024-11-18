package oidc4ci

import "github.com/dellekappa/vc-go/verifiable"

type DefaultLDPProofParser struct {
}

func NewDefaultLDPProofParser() *DefaultLDPProofParser {
	return &DefaultLDPProofParser{}
}

func (p *DefaultLDPProofParser) Parse(
	rawProof []byte,
	opt []verifiable.PresentationOpt,
) (*verifiable.Presentation, error) {
	return verifiable.ParsePresentation(rawProof,
		opt...,
	)
}
