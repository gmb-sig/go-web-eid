package webeidazugo

import (
	"encoding/base64"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
	"azugo.io/azugo/user"

	"github.com/gmb-sig/go-web-eid/certificate"
	"github.com/gmb-sig/go-web-eid/exceptions"
)

// Bind registers the four Web eID endpoints on the given router, each behind
// the EnsureSession pre-auth cookie middleware.
//
// CSRF protection must be enabled separately on the POST routes by the
// integrating application.
func (h *Handler) Bind(g azugo.Router) error {
	auth := g.Group("/auth")
	auth.Use(EnsureSession(h.config))
	auth.Get("/challenge", h.challenge)
	auth.Post("/login", h.login)

	sign := g.Group("/sign")
	sign.Use(EnsureSession(h.config))
	sign.Post("/certificate", h.signingCertificate)
	sign.Post("/finalize", h.finalize)
	return nil
}

// challenge issues a fresh challenge nonce bound to the session.
//
// @operationId WebEidChallenge
// @title Issue challenge nonce
// @success 200 ChallengeResponse response.ChallengeResponse "Challenge nonce"
// @resource WebEID
// @route /auth/challenge [get].
func (h *Handler) challenge(ctx *azugo.Context) {
	nonce, err := h.generator.GenerateAndStoreNonce(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(ChallengeResponse{Nonce: nonce.Base64EncodedNonce})
}

// login validates the authentication token and establishes the user.
//
// @operationId WebEidLogin
// @title Validate authentication token
// @param LoginRequest body request.LoginRequest true "Authentication token"
// @success 200 SubjectResponse response.SubjectResponse "Authenticated subject"
// @failure 401 {empty} "Unauthorized"
// @resource WebEID
// @route /auth/login [post].
func (h *Handler) login(ctx *azugo.Context) {
	var req LoginRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)
		return
	}

	stored, err := h.store.GetAndRemove(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}
	if stored.Expired(timeNow(), h.config.NonceTTL) {
		ctx.Error(exceptions.ErrChallengeNonceExpired)
		return
	}

	cert, err := h.validator.Validate(ctx, &req.AuthToken, stored.Base64EncodedNonce)
	if err != nil {
		ctx.Error(err)
		return
	}

	subject := subjectFromCertificate(cert)
	ctx.SetUser(user.New(map[string]token.ClaimStrings{
		"sub":         {subject.IDCode},
		"given_name":  {subject.GivenName},
		"family_name": {subject.Surname},
		"name":        {certificate.TitleCase(subject.GivenName + " " + subject.Surname)},
	}))
	ctx.JSON(subject)
}

// signingCertificate validates the signing certificate and negotiates the
// signature algorithm and hash function.
//
// @operationId WebEidSigningCertificate
// @title Validate signing certificate
// @param SigningCertificateRequest body request.SigningCertificateRequest true "Signing certificate"
// @success 200 SigningCertificateResponse response.SigningCertificateResponse "Negotiated algorithm"
// @failure 422 {empty} "Unprocessable entity"
// @resource WebEID
// @route /sign/certificate [post].
func (h *Handler) signingCertificate(ctx *azugo.Context) {
	var req SigningCertificateRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)
		return
	}
	der, err := base64.StdEncoding.DecodeString(req.Certificate)
	if err != nil {
		ctx.Error(exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, err))
		return
	}
	_, algo, hashFn, err := h.signer.PrepareSigning(ctx, der, req.SupportedSignatureAlgorithms)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(SigningCertificateResponse{SignatureAlgorithm: algo, HashFunction: hashFn})
}

// finalize returns the card's signed digest and authentication certificate to
// the caller for container finalization.
//
// @operationId WebEidFinalize
// @title Finalize signing
// @param FinalizeRequest body request.FinalizeRequest true "Signature value"
// @success 200 FinalizeResponse response.FinalizeResponse "OK"
// @failure 422 {empty} "Unprocessable entity"
// @resource WebEID
// @route /sign/finalize [post].
func (h *Handler) finalize(ctx *azugo.Context) {
	var req FinalizeRequest
	if err := ctx.Body.JSON(&req); err != nil {
		ctx.Error(err)
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		ctx.Error(exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, err))
		return
	}
	authDER, err := base64.StdEncoding.DecodeString(req.AuthCertificate)
	if err != nil {
		ctx.Error(exceptions.Wrap(exceptions.ErrSigningCertificateInvalid, err))
		return
	}
	if _, _, err := h.signer.Finalize(sig, authDER); err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(FinalizeResponse{Status: "ok"})
}
