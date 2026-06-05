package webeidazugo

import (
	"azugo.io/azugo"

	webeid "github.com/gmb-sig/go-web-eid"
	"github.com/gmb-sig/go-web-eid/signing"
)

// ChallengeResponse is returned by GET /auth/challenge.
type ChallengeResponse struct {
	Nonce string `json:"nonce"`
}

// LoginRequest is the body of POST /auth/login.
type LoginRequest struct {
	AuthToken webeid.AuthToken `json:"authToken" validate:"required"`
}

// Validate implements azugo.Validator.
func (r *LoginRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// SubjectResponse is the validated identity returned by POST /auth/login.
type SubjectResponse struct {
	CommonName  string `json:"commonName,omitempty"`
	IDCode      string `json:"idCode,omitempty"`
	CountryCode string `json:"countryCode,omitempty"`
	GivenName   string `json:"givenName,omitempty"`
	Surname     string `json:"surname,omitempty"`
}

// SigningCertificateRequest is the body of POST /sign/certificate.
type SigningCertificateRequest struct {
	// Certificate is the base64-encoded DER signing certificate.
	Certificate string `json:"certificate" validate:"required"`
	// SupportedSignatureAlgorithms are the algorithms the card reported.
	SupportedSignatureAlgorithms []signing.SignatureAlgorithm `json:"supportedSignatureAlgorithms" validate:"required,min=1"`
}

// Validate implements azugo.Validator.
func (r *SigningCertificateRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// SigningCertificateResponse is returned by POST /sign/certificate.
type SigningCertificateResponse struct {
	SignatureAlgorithm signing.SignatureAlgorithm `json:"signatureAlgorithm"`
	HashFunction       string                     `json:"hashFunction"`
}

// FinalizeRequest is the body of POST /sign/finalize.
type FinalizeRequest struct {
	// Signature is the base64-encoded raw card signature value (signed digest).
	Signature string `json:"signature" validate:"required"`
	// SignatureAlgorithm is the algorithm the card used.
	SignatureAlgorithm signing.SignatureAlgorithm `json:"signatureAlgorithm"`
	// AuthCertificate is the base64-encoded DER authentication certificate.
	AuthCertificate string `json:"authCertificate" validate:"required"`
}

// Validate implements azugo.Validator.
func (r *FinalizeRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// FinalizeResponse is returned by POST /sign/finalize.
type FinalizeResponse struct {
	Status string `json:"status"`
}
