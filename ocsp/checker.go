package ocsp

import (
	"bytes"
	"context"
	"crypto/x509"
	"time"

	"github.com/gmb-sig/go-web-eid/exceptions"
	xocsp "golang.org/x/crypto/ocsp"
)

// Options configures revocation checking behaviour. The zero value is not
// usable; use DefaultOptions and override as needed.
type Options struct {
	// Client is the transport used to send OCSP requests.
	Client Client
	// RequestTimeout bounds a single OCSP exchange.
	RequestTimeout time.Duration
	// Designated, when set, overrides the AIA responder for supported issuers.
	Designated *DesignatedServiceConfiguration
	// NonceDisabledURLs lists responder URLs that do not support the nonce
	// extension; requests to them omit the nonce.
	NonceDisabledURLs []string
	// AllowedResponseTimeSkew bounds clock skew for thisUpdate/nextUpdate.
	AllowedResponseTimeSkew time.Duration
	// MaxResponseThisUpdateAge bounds how old thisUpdate may be.
	MaxResponseThisUpdateAge time.Duration
	// Now overrides the clock used for freshness checks (primarily for testing).
	Now func() time.Time
}

// DefaultOptions returns the default OCSP options, matching the reference
// implementation defaults.
func DefaultOptions() Options {
	return Options{
		Client:                   &HTTPClient{},
		RequestTimeout:           5 * time.Second,
		AllowedResponseTimeSkew:  15 * time.Minute,
		MaxResponseThisUpdateAge: 2 * time.Minute,
		Now:                      time.Now,
	}
}

// Checker performs OCSP revocation checks for the configured options.
type Checker struct {
	opts Options
}

// NewChecker returns a Checker. Missing option fields fall back to defaults.
func NewChecker(opts Options) *Checker {
	def := DefaultOptions()
	if opts.Client == nil {
		opts.Client = def.Client
	}
	if opts.RequestTimeout <= 0 {
		opts.RequestTimeout = def.RequestTimeout
	}
	if opts.AllowedResponseTimeSkew <= 0 {
		opts.AllowedResponseTimeSkew = def.AllowedResponseTimeSkew
	}
	if opts.MaxResponseThisUpdateAge <= 0 {
		opts.MaxResponseThisUpdateAge = def.MaxResponseThisUpdateAge
	}
	if opts.Now == nil {
		opts.Now = def.Now
	}
	return &Checker{opts: opts}
}

// Check verifies that cert (issued by issuer) is not revoked. A nil error means
// the certificate is good.
func (c *Checker) Check(ctx context.Context, cert, issuer *x509.Certificate) error {
	responderURL, responderCert, nonceDisabled, err := c.resolveResponder(cert, issuer)
	if err != nil {
		return err
	}

	var nonce []byte
	if !nonceDisabled {
		nonce, err = generateNonce()
		if err != nil {
			return wrapOCSPError(err)
		}
	}

	reqBytes, err := buildRequest(cert, issuer, nonce)
	if err != nil {
		return wrapOCSPError(err)
	}

	respBytes, err := c.opts.Client.Do(ctx, responderURL, reqBytes, c.opts.RequestTimeout)
	if err != nil {
		return wrapOCSPError(err)
	}

	resp, err := parseAndVerify(respBytes, issuer, responderCert)
	if err != nil {
		return wrapOCSPError(err)
	}

	if nonce != nil {
		if got := responseNonce(resp); got != nil && !bytes.Equal(got, nonce) {
			return wrapOCSPError(errNonceMismatch)
		}
	}

	if err := c.checkFreshness(resp, c.opts.Now()); err != nil {
		return err
	}

	switch resp.Status {
	case xocsp.Good:
		return nil
	case xocsp.Revoked:
		return exceptions.ErrCertificateRevoked
	default:
		return wrapOCSPError(errUnknownStatus)
	}
}

// resolveResponder decides which responder URL and verification certificate to
// use, honouring the designated-service override and nonce-disabled list.
func (c *Checker) resolveResponder(cert, issuer *x509.Certificate) (url string, responderCert *x509.Certificate, nonceDisabled bool, err error) {
	if d := c.opts.Designated; d != nil && d.Supports(issuer) {
		return d.URL, d.ResponderCertificate, d.NonceDisabled, nil
	}
	url, err = AIAOCSPURL(cert)
	if err != nil {
		return "", nil, false, wrapOCSPError(err)
	}
	return url, nil, c.isNonceDisabled(url), nil
}

// isNonceDisabled reports whether the responder URL is in the nonce-disabled list.
func (c *Checker) isNonceDisabled(url string) bool {
	for _, u := range c.opts.NonceDisabledURLs {
		if u == url {
			return true
		}
	}
	return false
}

// checkFreshness validates thisUpdate/nextUpdate against the configured skew and
// maximum age.
func (c *Checker) checkFreshness(resp *xocsp.Response, now time.Time) error {
	skew := c.opts.AllowedResponseTimeSkew
	if resp.ThisUpdate.After(now.Add(skew)) {
		return wrapOCSPError(errThisUpdateInFuture)
	}
	if !resp.NextUpdate.IsZero() && resp.NextUpdate.Before(now.Add(-skew)) {
		return wrapOCSPError(errResponseExpired)
	}
	if now.Sub(resp.ThisUpdate) > c.opts.MaxResponseThisUpdateAge+skew {
		return wrapOCSPError(errThisUpdateTooOld)
	}
	return nil
}

// parseAndVerify parses an OCSP response and verifies its signature. When a
// designated responder certificate is supplied it is used for verification;
// otherwise the issuer is used (covering both issuer-signed and delegated
// responses embedded in the response).
func parseAndVerify(respBytes []byte, issuer, responderCert *x509.Certificate) (*xocsp.Response, error) {
	if responderCert != nil {
		return xocsp.ParseResponseForCert(respBytes, nil, responderCert)
	}
	return xocsp.ParseResponse(respBytes, issuer)
}
