package webeid

import (
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/gmb-sig/go-web-eid/certificate"
	"github.com/gmb-sig/go-web-eid/ocsp"
)

// AuthTokenValidatorBuilder builds an AuthTokenValidator. It mirrors the Java
// AuthTokenValidatorBuilder so existing RIA documentation maps onto it.
type AuthTokenValidatorBuilder struct {
	origin string

	trustedCAs []*x509.Certificate

	ocspEnabled          bool
	ocspClient           ocsp.Client
	ocspRequestTimeout   time.Duration
	designatedOCSP       *ocsp.DesignatedServiceConfiguration
	nonceDisabledOCSPURL []string
	ocspSkew             time.Duration
	ocspMaxThisUpdateAge time.Duration

	disallowedPolicies []asn1.ObjectIdentifier

	now func() time.Time
}

// NewAuthTokenValidatorBuilder returns a builder with reference-matching defaults
// (OCSP enabled, Mobile-ID policies disallowed).
func NewAuthTokenValidatorBuilder() *AuthTokenValidatorBuilder {
	return &AuthTokenValidatorBuilder{
		ocspEnabled:          true,
		ocspRequestTimeout:   5 * time.Second,
		ocspSkew:             15 * time.Minute,
		ocspMaxThisUpdateAge: 2 * time.Minute,
		disallowedPolicies:   certificate.DefaultDisallowedPolicies,
		now:                  time.Now,
	}
}

// WithSiteOrigin sets the origin the token is bound to, in the form
// https://host[:port] with no trailing slash (required).
func (b *AuthTokenValidatorBuilder) WithSiteOrigin(origin string) *AuthTokenValidatorBuilder {
	b.origin = origin
	return b
}

// WithTrustedCertificateAuthorities sets the intermediate CA trust anchors
// (required).
func (b *AuthTokenValidatorBuilder) WithTrustedCertificateAuthorities(cas ...*x509.Certificate) *AuthTokenValidatorBuilder {
	b.trustedCAs = append(b.trustedCAs, cas...)
	return b
}

// WithoutUserCertificateRevocationCheckWithOcsp disables OCSP revocation checks.
func (b *AuthTokenValidatorBuilder) WithoutUserCertificateRevocationCheckWithOcsp() *AuthTokenValidatorBuilder {
	b.ocspEnabled = false
	return b
}

// WithDesignatedOcspServiceConfiguration sets a designated OCSP responder.
func (b *AuthTokenValidatorBuilder) WithDesignatedOcspServiceConfiguration(cfg *ocsp.DesignatedServiceConfiguration) *AuthTokenValidatorBuilder {
	b.designatedOCSP = cfg
	return b
}

// WithOcspClient injects a custom OCSP transport.
func (b *AuthTokenValidatorBuilder) WithOcspClient(c ocsp.Client) *AuthTokenValidatorBuilder {
	b.ocspClient = c
	return b
}

// WithOcspRequestTimeout sets the per-request OCSP timeout.
func (b *AuthTokenValidatorBuilder) WithOcspRequestTimeout(d time.Duration) *AuthTokenValidatorBuilder {
	if d > 0 {
		b.ocspRequestTimeout = d
	}
	return b
}

// WithDisallowedCertificatePolicies sets the disallowed certificate policy OIDs,
// replacing the default Mobile-ID set.
func (b *AuthTokenValidatorBuilder) WithDisallowedCertificatePolicies(oids ...asn1.ObjectIdentifier) *AuthTokenValidatorBuilder {
	b.disallowedPolicies = oids
	return b
}

// WithNonceDisabledOcspUrls lists OCSP responders that lack nonce support.
func (b *AuthTokenValidatorBuilder) WithNonceDisabledOcspUrls(urls ...string) *AuthTokenValidatorBuilder {
	b.nonceDisabledOCSPURL = append(b.nonceDisabledOCSPURL, urls...)
	return b
}

// WithAllowedOcspResponseTimeSkew sets the allowed thisUpdate/nextUpdate skew.
func (b *AuthTokenValidatorBuilder) WithAllowedOcspResponseTimeSkew(d time.Duration) *AuthTokenValidatorBuilder {
	if d > 0 {
		b.ocspSkew = d
	}
	return b
}

// WithMaxOcspResponseThisUpdateAge sets the maximum thisUpdate age.
func (b *AuthTokenValidatorBuilder) WithMaxOcspResponseThisUpdateAge(d time.Duration) *AuthTokenValidatorBuilder {
	if d > 0 {
		b.ocspMaxThisUpdateAge = d
	}
	return b
}

// Build validates configuration and constructs the validator.
func (b *AuthTokenValidatorBuilder) Build() (AuthTokenValidator, error) {
	if b.origin == "" {
		return nil, errOriginRequired
	}
	normalizedOrigin, err := normalizeOrigin(b.origin)
	if err != nil {
		return nil, err
	}
	trust, err := certificate.NewTrustStore(b.trustedCAs...)
	if err != nil {
		return nil, err
	}

	v := &authTokenValidator{
		origin:             normalizedOrigin,
		trust:              trust,
		ocspEnabled:        b.ocspEnabled,
		disallowedPolicies: b.disallowedPolicies,
		now:                b.now,
	}
	if b.ocspEnabled {
		v.ocspChecker = ocsp.NewChecker(ocsp.Options{
			Client:                   b.ocspClient,
			RequestTimeout:           b.ocspRequestTimeout,
			Designated:               b.designatedOCSP,
			NonceDisabledURLs:        b.nonceDisabledOCSPURL,
			AllowedResponseTimeSkew:  b.ocspSkew,
			MaxResponseThisUpdateAge: b.ocspMaxThisUpdateAge,
		})
	}
	return v, nil
}
