package mitmpgo

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

type UnifiedTransport struct {
	defaultTransport http.RoundTripper
	h2cTransport     http.RoundTripper
}

func (t *UnifiedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.ProtoMajor == 2 && req.TLS == nil {
		// if proxy grpc message without tls, use h2c transport
		return t.h2cTransport.RoundTrip(req)
	}
	return t.defaultTransport.RoundTrip(req)
}

func NewTransport(dialFn func(ctx context.Context, network, addr string) (net.Conn, error)) *UnifiedTransport {
	// configure transport
	return &UnifiedTransport{
		defaultTransport: &http.Transport{
			IdleConnTimeout:       time.Second * 60,
			MaxIdleConns:          100,
			ResponseHeaderTimeout: time.Second * 10,
			ReadBufferSize:        4 * 1024,
			WriteBufferSize:       4 * 1024,
			DialContext:           dialFn,
			DialTLSContext:        dialFn,
			ForceAttemptHTTP2:     true,
		},
		h2cTransport: &http2.Transport{
			AllowHTTP:        true,
			IdleConnTimeout:  time.Second * 60,
			PingTimeout:      time.Second * 15,
			ReadIdleTimeout:  time.Second * 20,
			WriteByteTimeout: time.Second * 30,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return dialFn(ctx, network, addr)
			},
		},
	}
}
