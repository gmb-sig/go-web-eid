package webeidazugo

import (
	"crypto/x509"
	"errors"
	"os"

	webeid "github.com/gmb-sig/go-web-eid"
	"github.com/gmb-sig/go-web-eid/certificate"
	"github.com/gmb-sig/go-web-eid/ocsp"
	"github.com/gmb-sig/go-web-eid/signing"
)

// Handler wires the go-web-eid core into Azugo routes. Construct it with New
// and register its endpoints with Bind.
type Handler struct {
	config    *Configuration
	validator webeid.AuthTokenValidator
	generator webeid.ChallengeNonceGenerator
	store     webeid.ChallengeNonceStore
	signer    *signing.Signer
}

// New builds a Handler from configuration, loading the trusted intermediate CA
// certificates and wiring the validator, nonce generator and signer.
func New(cfg *Configuration) (*Handler, error) {
	if cfg == nil {
		return nil, errors.New("webeid: configuration is required")
	}

	cas, err := loadTrustedCAs(cfg.TrustedCACertsPath)
	if err != nil {
		return nil, err
	}
	trust, err := certificate.NewTrustStore(cas...)
	if err != nil {
		return nil, err
	}

	validator, err := buildValidator(cfg, cas)
	if err != nil {
		return nil, err
	}

	store := NewSessionStore(cfg)
	generator, err := webeid.NewChallengeNonceGeneratorBuilder().
		WithChallengeNonceStore(store).
		WithNonceTTL(cfg.NonceTTL).
		Build()
	if err != nil {
		return nil, err
	}

	signerOpts := signing.Options{
		HashPreference: cfg.SigningHashPreference,
		Trust:          trust,
	}
	if cfg.OCSPEnabled {
		signerOpts.OCSPChecker = ocsp.NewChecker(ocsp.Options{
			RequestTimeout:    cfg.OCSPRequestTimeout,
			Designated:        designatedConfig(cfg),
			NonceDisabledURLs: nil,
		})
	}
	signer, err := signing.NewSigner(signerOpts)
	if err != nil {
		return nil, err
	}

	return &Handler{
		config:    cfg,
		validator: validator,
		generator: generator,
		store:     store,
		signer:    signer,
	}, nil
}

// buildValidator constructs the auth-token validator from configuration.
func buildValidator(cfg *Configuration, cas []*x509.Certificate) (webeid.AuthTokenValidator, error) {
	b := webeid.NewAuthTokenValidatorBuilder().
		WithSiteOrigin(cfg.Origin).
		WithTrustedCertificateAuthorities(cas...).
		WithOcspRequestTimeout(cfg.OCSPRequestTimeout)
	if !cfg.OCSPEnabled {
		b.WithoutUserCertificateRevocationCheckWithOcsp()
	}
	if d := designatedConfig(cfg); d != nil {
		b.WithDesignatedOcspServiceConfiguration(d)
	}
	return b.Build()
}

// designatedConfig returns the designated OCSP responder configuration, if set.
func designatedConfig(cfg *Configuration) *ocsp.DesignatedServiceConfiguration {
	if cfg.DesignatedOCSPURL == "" {
		return nil
	}
	return &ocsp.DesignatedServiceConfiguration{URL: cfg.DesignatedOCSPURL}
}

// loadTrustedCAs loads intermediate CA certificates from a file or directory.
func loadTrustedCAs(path string) ([]*x509.Certificate, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return certificate.LoadCertificatesFromDir(path)
	}
	f, err := os.Open(path) //nolint:gosec // operator-controlled trust material
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return certificate.LoadCertificatesFromPEM(f)
}
