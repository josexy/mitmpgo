package mitmpgo

import (
	"crypto/x509"
	"net"
	"time"

	"github.com/josexy/mitmpgo/internal/cert"
)

type Option interface {
	apply(*options)
}

type OptionFunc func(*options)

func (f OptionFunc) apply(o *options) { f(o) }

// options holds all configuration parameters for the MITM proxy handler.
type options struct {
	proxy         string      // Upstream proxy URL (e.g., "http://127.0.0.1:8080")
	caCertPath    string      // Path to the CA certificate file for TLS interception
	caKeyPath     string      // Path to the CA private key file for TLS interception
	skipVerifySSL bool        // Skip SSL certificate verification when connecting to servers
	disableHTTP2  bool        // Disable HTTP/2 support, use HTTP/1.1 only
	disableProxy  bool        // Disable upstream proxy usage
	includeHosts  []string    // Whitelist of hosts to intercept (supports wildcards)
	excludeHosts  []string    // Blacklist of hosts to exclude from interception (supports wildcards)
	rootCAs       []string    // Paths to additional root CA certificate files
	dialer        *net.Dialer // Custom dialer for outbound connections

	// Certificate cache pool configuration
	certCachePool struct {
		Capacity     int // Maximum number of cached certificates
		Interval     int // Cache cleanup interval in milliseconds
		ExpireSecond int // Certificate cache expiration time in milliseconds
	}

	rootCACertPool *x509.CertPool // System and custom root CA certificate pool
	caCert         *cert.Cert     // Loaded CA certificate for TLS interception
}

// newOptions creates a new options instance with default values.
// Default dialer timeout is 15 seconds.
func newOptions(opt ...Option) *options {
	options := &options{
		dialer: &net.Dialer{Timeout: 15 * time.Second},
	}
	for _, o := range opt {
		o.apply(options)
	}
	return options
}

// WithProxy configures an upstream proxy server for outbound connections.
//
// The proxy parameter should be a URL in one of these formats:
//   - HTTP proxy: "http://proxy.example.com:8080"
//   - HTTPS proxy: "https://proxy.example.com:8080"
//   - SOCKS5 proxy: "socks5://proxy.example.com:1080"
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithProxy("http://127.0.0.1:8080"),
//	)
func WithProxy(proxy string) Option {
	return OptionFunc(func(o *options) {
		o.proxy = proxy
	})
}

// WithDisableProxy disables the use of any upstream proxy server.
// All connections will be made directly to the destination server.
// This option takes precedence over WithProxy if both are specified.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithDisableProxy(),
//	)
func WithDisableProxy() Option {
	return OptionFunc(func(o *options) {
		o.disableProxy = true
	})
}

// WithCACertPath specifies the path to the CA certificate file.
// This certificate is used to sign dynamically generated certificates for TLS interception.
//
// Required for TLS interception to work properly.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithCACertPath("certs/ca.crt"),
//	    WithCAKeyPath("certs/ca.key"),
//	)
func WithCACertPath(caCertPath string) Option {
	return OptionFunc(func(o *options) {
		o.caCertPath = caCertPath
	})
}

// WithCAKeyPath specifies the path to the CA private key file.
// This private key is used together with the CA certificate to sign dynamically generated
// certificates for intercepted HTTPS connections.
//
// Required for TLS interception to work properly.
// The key file must match the CA certificate specified with WithCACertPath.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithCACertPath("certs/ca.crt"),
//	    WithCAKeyPath("certs/ca.key"),
//	)
func WithCAKeyPath(caKeyPath string) Option {
	return OptionFunc(func(o *options) {
		o.caKeyPath = caKeyPath
	})
}

// WithRootCAs adds additional trusted root CA certificates for verifying server certificates.
// This is useful when connecting to servers that use certificates signed by custom or internal CAs.
//
// The system's default root CA pool is used as the base, and these certificates are added to it.
// Multiple certificate file paths can be provided.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithRootCAs("certs/internal-ca.crt", "certs/partner-ca.crt"),
//	)
func WithRootCAs(rootCAPaths ...string) Option {
	return OptionFunc(func(o *options) {
		o.rootCAs = rootCAPaths
	})
}

// WithDialer sets a custom dialer for establishing outbound connections.
// This allows fine-grained control over connection behavior such as timeouts,
// keep-alive settings, and local address binding.
//
// If not specified, a default dialer with a 10-second timeout is used.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithDialer(&net.Dialer{
//	        Timeout:   30 * time.Second,
//	    }),
//	)
func WithDialer(dialer *net.Dialer) Option {
	return OptionFunc(func(o *options) {
		o.dialer = dialer
	})
}

// WithSkipVerifySSLFromServer disables SSL certificate verification when the proxy
// connects to upstream servers. This allows connecting to servers with self-signed
// certificates or invalid certificate chains.
//
// WARNING: This option should only be used for testing or development purposes.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithSkipVerifySSLFromServer(),
//	)
func WithSkipVerifySSLFromServer() Option {
	return OptionFunc(func(o *options) {
		o.skipVerifySSL = true
	})
}

// WithDisableHTTP2 disables HTTP/2 support in the proxy.
// When enabled, all connections will use HTTP/1.1 even if both client and server support HTTP/2.
// This also disables h2c (HTTP/2 over cleartext) support.
//
// This can be useful for debugging or when working with applications that have
// issues with HTTP/2 implementations.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithDisableHTTP2(),
//	)
func WithDisableHTTP2() Option {
	return OptionFunc(func(o *options) {
		o.disableHTTP2 = true
	})
}

// WithCertCachePool configures the certificate cache pool parameters.
// The cache stores dynamically generated certificates to avoid regenerating them
// for frequently accessed domains, which improves performance.
//
// Parameters:
//   - capacity: Maximum number of certificates to cache (e.g., 1000)
//   - interval: How often to run cache cleanup in milliseconds (e.g., 60000 for 1 minute)
//   - expireSecond: How long certificates stay in cache in milliseconds (e.g., 3600000 for 1 hour)
//
// If not specified, default values are used.
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithCertCachePool(
//	        1000,    // Cache up to 1000 certificates
//	        60000,   // Check for expired entries every 60 seconds
//	        3600000, // Expire cached certificates after 1 hour
//	    ),
//	)
func WithCertCachePool(capacity, interval, expireSecond int) Option {
	return OptionFunc(func(o *options) {
		o.certCachePool.Capacity = capacity
		o.certCachePool.Interval = interval
		o.certCachePool.ExpireSecond = expireSecond
	})
}

// WithIncludeHosts specifies a whitelist of hosts that should be intercepted.
// Only traffic to these hosts will be intercepted; all other traffic will pass through
// without interception (passthrough mode).
//
// Supports wildcard patterns:
//   - "example.com" - exact match
//   - "*.example.com" - matches any subdomain of example.com
//   - "api.*.example.com" - matches api.staging.example.com, api.prod.example.com, etc.
//
// If this option is not used, all hosts are intercepted by default
// (unless excluded with WithExcludeHosts).
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithIncludeHosts(
//	        "api.example.com",
//	        "*.internal.example.com",
//	        "test.example.org",
//	    ),
//	)
func WithIncludeHosts(hosts ...string) Option {
	return OptionFunc(func(o *options) {
		o.includeHosts = hosts
	})
}

// WithExcludeHosts specifies a blacklist of hosts that should NOT be intercepted.
// Traffic to these hosts will pass through without interception (passthrough mode).
//
// Supports wildcard patterns:
//   - "cdn.example.com" - exact match
//   - "*.cdn.com" - matches any subdomain of cdn.com
//   - "static.*.example.com" - matches static.prod.example.com, static.dev.example.com, etc.
//
// This is useful for excluding CDN domains, static content servers, or domains
// that don't need inspection to improve performance.
//
// If both WithIncludeHosts and WithExcludeHosts are used:
//   - WithExcludeHosts takes precedence
//   - A host matching the exclude list will never be intercepted
//   - A host not in the include list will be passed through
//
// Example:
//
//	handler, err := NewMitmProxyHandler(
//	    WithExcludeHosts(
//	        "*.cdn.com",
//	        "static.example.com",
//	        "*.cloudfront.net",
//	    ),
//	)
func WithExcludeHosts(hosts ...string) Option {
	return OptionFunc(func(o *options) {
		o.excludeHosts = hosts
	})
}
