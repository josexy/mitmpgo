package mitmpgo

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/gorilla/websocket"
	"github.com/josexy/mitmpgo/internal/cert"
	"github.com/josexy/mitmpgo/internal/iocopy"
	"github.com/josexy/mitmpgo/metadata"
	"golang.org/x/net/http2"
)

var (
	ErrServerCertUnavailable = errors.New("cannot found an available server tls certificate")
	ErrShortTLSPacket        = errors.New("short tls packet")
	ErrRequestContextMissing = errors.New("request context missing")
	ErrInvalidProxyRequest   = errors.New("invalid proxy request")
	ErrHijackNotSupported    = errors.New("http response hijack not supported")
)

type contextKey string

const preboundConnKey contextKey = "prebound-net-conn"

type reqContextKey struct{}

type ReqContext struct {
	Hostport string
	Request  *http.Request
}

func AppendToRequestContext(ctx context.Context, hostport string, request *http.Request) context.Context {
	reqCtx := ReqContext{
		Hostport: hostport,
		Request:  request,
	}
	return context.WithValue(ctx, reqContextKey{}, reqCtx)
}

func FromRequestContext(ctx context.Context) (ReqContext, bool) {
	reqCtx, ok := ctx.Value(reqContextKey{}).(ReqContext)
	if !ok {
		return ReqContext{}, false
	}
	return reqCtx, true
}

func ParseHostPort(req *http.Request) (string, error) {
	var target string
	if req.Method != http.MethodConnect {
		target = req.Host
	} else {
		target = req.RequestURI
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil || port == "" {
		host = target
		if req.Method != http.MethodConnect {
			port = "80"
		}
		// ipv6
		if len(host) > 0 && host[0] == '[' {
			host = target[1 : len(host)-1]
		}
	}
	if len(host) == 0 {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

var _ http.Hijacker = (*fakeHttpResponseWriter)(nil)
var _ http.ResponseWriter = (*fakeHttpResponseWriter)(nil)

type fakeHttpResponseWriter struct {
	conn   net.Conn
	bufRW  *bufio.ReadWriter
	header http.Header
}

func newFakeHttpResponseWriter(conn net.Conn) *fakeHttpResponseWriter {
	return &fakeHttpResponseWriter{
		header: make(http.Header),
		conn:   conn,
		bufRW:  bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
	}
}

// Hijack hijack the connection for websocket
func (f *fakeHttpResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return f.conn, f.bufRW, nil
}

// implemented http.ResponseWriter but nothing to do
func (f *fakeHttpResponseWriter) Header() http.Header       { return f.header }
func (f *fakeHttpResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (f *fakeHttpResponseWriter) WriteHeader(int)           {}

type ErrorContext struct {
	RemoteAddr string
	Hostport   string
	Error      error
}

type ErrorHandler func(ErrorContext)

type MitmProxyHandler interface {
	CACertPath() string

	// low-level api
	Serve(context.Context, net.Conn) error
	// high-level application api
	ServeSOCKS5(context.Context, net.Conn) error
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type mitmProxyHandler struct {
	*options
	proxyDialer   *proxyDialer
	priKeyPool    *priKeyPool
	certPool      *certPool
	h2s           *http2.Server
	transport     *UnifiedTransport
	domainMatcher struct {
		include *trieNode
		exclude *trieNode
	}
}

func NewMitmProxyHandler(opt ...Option) (MitmProxyHandler, error) {
	opts := newOptions(opt...)
	var err error
	opts.caCert, err = cert.LoadCACertificate(opts.caCertPath, opts.caKeyPath)
	if err != nil {
		return nil, err
	}
	if len(opts.rootCAs) > 0 {
		opts.rootCACertPool, err = x509.SystemCertPool()
		if err != nil || opts.rootCACertPool == nil {
			opts.rootCACertPool = x509.NewCertPool()
		}
		for _, path := range opts.rootCAs {
			ca, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			if ok := opts.rootCACertPool.AppendCertsFromPEM(ca); !ok {
				return nil, errors.New("failed to append ca file to cert pool")
			}
		}
	}
	proxyURL, err := parseProxyFrom(opts.disableProxy, opts.proxy)
	if err != nil {
		return nil, err
	}

	dialFn := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if preboundConn, ok := ctx.Value(preboundConnKey).(net.Conn); ok {
			return preboundConn, nil
		}
		return nil, errors.New("no prebound connection")
	}

	includeMatcher, excludeMatcher := newTrieNode(), newTrieNode()
	for _, host := range opts.includeHosts {
		includeMatcher.insert(host)
	}
	for _, host := range opts.excludeHosts {
		excludeMatcher.insert(host)
	}

	handler := &mitmProxyHandler{
		options: opts,
		h2s: &http2.Server{
			IdleTimeout:      time.Second * 60, // idle connection timeout
			PingTimeout:      time.Second * 15,
			ReadIdleTimeout:  time.Second * 20,
			WriteByteTimeout: time.Second * 30,
		},
		transport:   NewTransport(dialFn),
		proxyDialer: NewProxyDialer(proxyURL, opts.dialer),
		priKeyPool:  newPriKeyPool(opts.certCachePool.Capacity),
		certPool: newCertPool(opts.certCachePool.Capacity,
			time.Duration(opts.certCachePool.Interval)*time.Millisecond,
			time.Duration(opts.certCachePool.ExpireSecond)*time.Millisecond,
		),
	}
	handler.domainMatcher.include = includeMatcher
	handler.domainMatcher.exclude = excludeMatcher
	handler.chainHTTPInterceptors()
	handler.chainWebsocketInterceptors()
	return handler, nil
}

func (r *mitmProxyHandler) chainHTTPInterceptors() {
	interceptors := r.chainHttpInts
	if r.httpInt != nil {
		interceptors = append([]HTTPInterceptor{r.httpInt}, r.chainHttpInts...)
	}
	var chainedInt HTTPInterceptor
	if len(interceptors) == 0 {
		chainedInt = nil
	} else if len(interceptors) == 1 {
		chainedInt = interceptors[0]
	} else {
		chainedInt = chainHTTPInterceptors(interceptors)
	}
	r.httpInt = chainedInt
}

func (r *mitmProxyHandler) chainWebsocketInterceptors() {
	interceptors := r.chainWsInts
	if r.wsInt != nil {
		interceptors = append([]WebsocketInterceptor{r.wsInt}, r.chainWsInts...)
	}
	var chainedInt WebsocketInterceptor
	if len(interceptors) == 0 {
		chainedInt = nil
	} else if len(interceptors) == 1 {
		chainedInt = interceptors[0]
	} else {
		chainedInt = chainWebsocketInterceptors(interceptors)
	}
	r.wsInt = chainedInt
}

func (r *mitmProxyHandler) CACertPath() string {
	return r.caCertPath
}

func (r *mitmProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var err error
	remoteAddr, hostport := req.RemoteAddr, ""
	defer func() {
		if err != nil {
			r.handleError(ErrorContext{
				RemoteAddr: remoteAddr,
				Hostport:   hostport,
				Error:      err,
			})
		}
	}()
	hj, ok := w.(http.Hijacker)
	if !ok {
		err = ErrHijackNotSupported
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	request := req
	hostport, err = ParseHostPort(req)
	if err != nil {
		return
	}
	if req.Method == http.MethodConnect {
		request = nil
		conn.Write(HttpResponseConnectionEstablished)
	} else if req.URL != nil && len(req.URL.Scheme) == 0 {
		// directly access proxy server and url scheme is empty
		err = ErrInvalidProxyRequest
		return
	}
	err = r.Serve(AppendToRequestContext(req.Context(), hostport, request), conn)
}

func (r *mitmProxyHandler) ServeSOCKS5(ctx context.Context, conn net.Conn) error {
	var hostport string
	var err error
	defer func() {
		if err != nil {
			r.handleError(ErrorContext{
				RemoteAddr: conn.RemoteAddr().String(),
				Hostport:   hostport,
				Error:      err,
			})
		}
	}()
	if err = r.handleSocks5Handshake(ctx, conn); err != nil {
		return err
	}
	if hostport, err = r.handleSocks5Request(ctx, conn); err != nil {
		return err
	}
	err = r.Serve(AppendToRequestContext(ctx, hostport, nil), conn)
	return err
}

func (r *mitmProxyHandler) Serve(ctx context.Context, conn net.Conn) error {
	reqCtx, ok := FromRequestContext(ctx)
	if !ok {
		return ErrRequestContextMissing
	}

	nowTs := time.Now()

	if r.shouldPassthroughRequest(reqCtx.Hostport) {
		return r.passthroughTunnel(ctx, conn)
	}

	md := metadata.NewMD()
	md.Set(metadata.ConnectionEstablishedTs, nowTs)
	md.Set(metadata.RequestReceivedTs, nowTs)
	md.Set(metadata.RequestHostport, reqCtx.Hostport)
	md.Set(metadata.ConnectionSourceAddrPort, getAddrPortFromConn(conn))
	ctx = metadata.AppendToContext(ctx, md)

	return r.handleTunnelRequest(ctx, conn, reqCtx.Request != nil)
}

func (r *mitmProxyHandler) shouldPassthroughRequest(hostport string) bool {
	host, _, _ := net.SplitHostPort(hostport)

	if len(r.excludeHosts) > 0 {
		if found := r.domainMatcher.exclude.match(host); found {
			// passthrough
			return true
		}
	}

	if len(r.includeHosts) > 0 {
		found := r.domainMatcher.include.match(host)
		return !found
	}

	// not passthrough
	return false
}

func (r *mitmProxyHandler) passthroughTunnel(ctx context.Context, srcConn net.Conn) error {
	reqCtx, _ := FromRequestContext(ctx)
	dstConn, err := r.proxyDialer.DialTCPContext(ctx, reqCtx.Hostport)
	if err != nil {
		return err
	}
	// only write the request for none-CONNECT request
	if reqCtx.Request != nil {
		// we should copy the request to dst connection firstly
		// TODO: if upload large file, this will cause performance problem
		if err = reqCtx.Request.Write(dstConn); err != nil {
			return err
		}
	}
	return iocopy.IoCopyBidirectional(dstConn, srcConn)
}

func (r *mitmProxyHandler) handleError(ec ErrorContext) {
	if r.errHandler != nil && ec.Error != nil {
		r.errHandler(ec)
	}
}

func (r *mitmProxyHandler) initiateSSLHandshakeWithClientHello(ctx context.Context, chi *tls.ClientHelloInfo) (net.Conn, *tls.Config, error) {
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)

	serverName := chi.ServerName
	protos := chi.SupportedProtos

	if r.disableHTTP2 {
		protos = slices.DeleteFunc(protos, func(e string) bool { return e == http2.NextProtoTLS })
	}

	host, _, _ := net.SplitHostPort(reqCtx.Hostport)
	if serverName == "" {
		serverName = host
	}
	dstConn, err := r.proxyDialer.DialTCPContext(ctx, reqCtx.Hostport)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig := &tls.Config{
		// Get clientHello alpnProtocols from client and forward to server
		NextProtos:   protos,
		CipherSuites: chi.CipherSuites,
		RootCAs:      r.rootCACertPool,
	}
	if r.skipVerifySSL {
		tlsConfig.InsecureSkipVerify = true
	} else if serverName != "" {
		tlsConfig.ServerName = serverName
	}
	tlsClientConn := tls.Client(dstConn, tlsConfig)
	// send client hello and do tls handshake
	if err = tlsClientConn.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	tlsConnEstTs := time.Now()
	cs := tlsClientConn.ConnectionState()

	// Get server certificate from local cache pool
	if serverCert, err := r.certPool.Get(host); err == nil {
		return tlsClientConn, &tls.Config{
			// Server selected negotiated protocol
			NextProtos:   []string{cs.NegotiatedProtocol},
			Certificates: []tls.Certificate{serverCert},
		}, nil
	}
	var foundCert *x509.Certificate
	for _, cert := range cs.PeerCertificates {
		if !cert.IsCA {
			foundCert = cert
		}
	}
	if foundCert == nil {
		return nil, nil, ErrServerCertUnavailable
	}
	// Get private key from local cache pool
	privateKey, err := r.priKeyPool.Get()
	if err != nil {
		return nil, nil, err
	}
	serverCert, err := cert.NewCertificateBuilder().
		ServerAuth().
		ValidateDays(365).
		PrivateKey(privateKey).
		Subject(foundCert.Subject).
		DNSNames(foundCert.DNSNames).
		IPAddresses(foundCert.IPAddresses).
		BuildFromCA(r.caCert)
	if err != nil {
		return nil, nil, err
	}

	md.Set(metadata.SSLHandshakeCompletedTs, tlsConnEstTs)
	md.Set(metadata.ConnectionTLSState, &metadata.TLSState{
		ServerName:          chi.ServerName,
		CipherSuites:        chi.CipherSuites,
		TLSVersions:         chi.SupportedVersions,
		ALPN:                chi.SupportedProtos,
		SelectedCipherSuite: cs.CipherSuite,
		SelectedTLSVersion:  cs.Version,
		SelectedALPN:        cs.NegotiatedProtocol,
	})
	md.Set(metadata.ConnectionServerCertificate, &metadata.ServerCertificate{
		Version:            foundCert.Version,
		SerialNumber:       foundCert.SerialNumber,
		SignatureAlgorithm: foundCert.SignatureAlgorithm,
		Subject:            foundCert.Subject,
		Issuer:             foundCert.Issuer,
		NotBefore:          foundCert.NotBefore,
		NotAfter:           foundCert.NotAfter,
		DNSNames:           foundCert.DNSNames,
		IPAddresses:        foundCert.IPAddresses,
		RawContent:         foundCert.Raw,
	})

	certificate := serverCert.Certificate()
	r.certPool.Set(host, certificate)
	return tlsClientConn, &tls.Config{
		// Server selected negotiated protocol
		NextProtos:   []string{cs.NegotiatedProtocol},
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func isTLSRequest(data []byte) bool {
	// Check TLS Record Layer: Handshake Protocol
	// data[0]: ContentType: Handshake(0x16)
	// data[1:2]: ProtocolVersion: TLS 1.0(0x0301), TLS 1.1(0x0302), TLS 1.2(0x0303)
	// data[5]: HandshakeType: (Client Hello: 0x1)
	return data[0] == 0x16 && data[1] == 0x3 && (data[2] >= 0x1 && data[2] <= 0x3) && data[5] == 0x1
}

func (r *mitmProxyHandler) handleTunnelRequest(ctx context.Context, conn net.Conn, consumedRequest bool) (err error) {
	var data []byte

	if !consumedRequest {
		bufConn := newBufConn(conn)
		data, err = bufConn.Peek(6)
		if err != nil {
			return err
		}
		conn = bufConn
	}

	var srcConn, dstConn net.Conn
	// Check if the common http/websocket request with tls
	if len(data) >= 6 && isTLSRequest(data) {
		clientHelloInfoCh := make(chan *tls.ClientHelloInfo, 1)
		tlsConnCh := make(chan net.Conn, 1)
		tlsConfigCh := make(chan *tls.Config, 1)
		errCh := make(chan error, 1)
		tlsConn := tls.Server(conn, &tls.Config{
			GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
				clientHelloInfoCh <- chi
				select {
				case err := <-errCh:
					return nil, err
				case cfg := <-tlsConfigCh:
					return cfg, nil
				}
			},
		})
		go func() {
			chi, ok := <-clientHelloInfoCh
			if !ok {
				return
			}
			conn, tlsConfig, err := r.initiateSSLHandshakeWithClientHello(ctx, chi)
			if err != nil {
				errCh <- err
			} else {
				tlsConfigCh <- tlsConfig
				tlsConnCh <- conn
			}
		}()
		// read client hello and do tls handshake
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			// if tls handshake failed before GetConfigForClient(),
			// we should close the channel in order to quit the goroutine
			close(clientHelloInfoCh)
			select {
			case conn := <-tlsConnCh:
				// if tls handshake failed after GetConfigForClient() succeed,
				// we should close the tls connection if it has been created
				conn.Close()
			default:
				// tls handshake failed if GetConfigForClient() failed
			}
			return err
		}
		// wait for tls handshake
		dstConn = <-tlsConnCh

		state := tlsConn.ConnectionState()
		// If the result of the negotiation is http2,
		// then we should hand over the process of processing the http2 stream to the underlying go http2 library,
		// and finally we only need to get the [http.Request] and process the [http.ResponseWriter].
		// Early process http2
		if state.NegotiatedProtocol == http2.NextProtoTLS {
			defer dstConn.Close()
			r.h2s.ServeConn(tlsConn, &http2.ServeConnOpts{
				Context: ctx,
				Handler: r.serveHTTP2Handler(ctx, dstConn),
			})
			return
		}
		srcConn = tlsConn
	} else {
		reqCtx, _ := FromRequestContext(ctx)
		dstConn, err = r.proxyDialer.DialTCPContext(ctx, reqCtx.Hostport)
		if err != nil {
			return
		}
		srcConn = conn
	}
	defer dstConn.Close()

	ctx, earlyDone, isWsUpgrade, err := r.distinguishHTTPRequest(ctx, srcConn, dstConn)
	if err != nil || earlyDone {
		return
	}
	if isWsUpgrade {
		return r.relayConnForWS(ctx, srcConn, dstConn)
	}
	return r.relayConnForHTTP(ctx, srcConn, dstConn)
}

func (r *mitmProxyHandler) handleH2CRequest(ctx context.Context, rw http.ResponseWriter, req *http.Request, dstConn net.Conn) (bool, error) {
	// Handle h2c with prior knowledge (RFC 7540 Section 3.4)
	if req.Method == "PRI" && len(req.Header) == 0 && req.URL.Path == "*" && req.Proto == "HTTP/2.0" {
		conn, err := initH2CWithPriorKnowledge(rw)
		if err != nil {
			return false, err
		}
		r.h2s.ServeConn(conn, &http2.ServeConnOpts{
			Context:          ctx,
			Handler:          r.serveHTTP2Handler(ctx, dstConn),
			SawClientPreface: true,
		})
		return true, nil
	}
	// Handle Upgrade to h2c (RFC 7540 Section 3.2)
	if isH2CUpgrade(req.Header) {
		removeHopByHopRequestHeaders(req.Header)
		conn, settings, err := upgradeH2C(rw, req)
		if err != nil {
			return false, err
		}
		req.Header.Del(HttpHeaderHttp2Settings)
		r.h2s.ServeConn(conn, &http2.ServeConnOpts{
			Context:        ctx,
			Handler:        r.serveHTTP2Handler(ctx, dstConn),
			UpgradeRequest: req,
			Settings:       settings,
		})
		return true, nil
	}
	return false, nil
}

func (r *mitmProxyHandler) distinguishHTTPRequest(ctx context.Context, srcConn, dstConn net.Conn) (newCtx context.Context, earlyDone bool, upgrade bool, retErr error) {
	reqCtx, _ := FromRequestContext(ctx)

	// Read the http request for https/wss via tls tunnel
	fakerw := newFakeHttpResponseWriter(srcConn)
	request := reqCtx.Request

	// Need to read the request
	if request == nil {
		_, rw, err := fakerw.Hijack()
		if err != nil {
			retErr = err
			return
		}
		request, err = http.ReadRequest(rw.Reader)
		if err != nil {
			retErr = err
			return
		}
	}

	if !r.disableHTTP2 {
		// If it's a SOCKS proxy, then the request might be h2c.
		earlyDone, retErr = r.handleH2CRequest(ctx, fakerw, request, dstConn)
		if retErr != nil || earlyDone {
			return
		}
	}

	// The request url scheme can be either http or https and we don't care for HTTP1 transport
	// Because the inner Dial and DialTLS functions were overwritten and replaced with custom net.Conn
	request.URL.Scheme = "http"
	request.URL.Host = request.Host

	if upgrade = isWSUpgrade(request.Header); upgrade {
		request.URL.Scheme = "ws"
	}

	// patch the new request to the request context
	reqCtx.Request = request
	newCtx = AppendToRequestContext(ctx, reqCtx.Hostport, reqCtx.Request)

	return
}

func (r *mitmProxyHandler) relayConnForWS(ctx context.Context, srcConn, dstConn net.Conn) (err error) {
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	upgrader.Subprotocols = []string{reqCtx.Request.Header.Get("Sec-WebSocket-Protocol")}
	fakeWriter := newFakeHttpResponseWriter(srcConn)

	// Response to client: HTTP/1.1 101 Switching Protocols
	// Convert net.Conn to websocket.Conn for reading and sending websocket messages
	wsSrcConn, err := upgrader.Upgrade(fakeWriter, reqCtx.Request, nil)
	if err != nil {
		return err
	}

	dialer := &websocket.Dialer{
		// override the dial func
		NetDialContext:    func(context.Context, string, string) (net.Conn, error) { return dstConn, nil },
		NetDialTLSContext: func(context.Context, string, string) (net.Conn, error) { return dstConn, nil },
	}

	// Delete websocket related headers here and re-wrapper them via websocket.Dialer DialContext
	removeWebsocketRequestHeaders(reqCtx.Request.Header)
	// Connect to the real websocket server with the same client request header
	wsDstConn, resp, err := dialer.DialContext(ctx, reqCtx.Request.URL.String(), reqCtx.Request.Header)
	if err != nil {
		return err
	}
	resp.Body.Close()

	errCh := make(chan error, 2)
	relayWSMessage := func(dir WSDirection, src, dst *websocket.Conn) {
		for {
			msgType, buffer, err := readBufferFromWSConn(src)
			if err != nil {
				errCh <- err
				break
			}
			if r.wsInt != nil {
				md.Set(metadata.ConnectionDestinationAddrPort, getAddrPortFromConn(dstConn))
				r.wsInt(ctx, dir, msgType, buffer, reqCtx.Request, wrapperInvoker(dst.WriteMessage))
			} else {
				dst.WriteMessage(msgType, buffer.Bytes())
			}
			releaseBuffer(buffer)
		}
	}
	go relayWSMessage(Send, wsSrcConn, wsDstConn)
	go relayWSMessage(Receive, wsDstConn, wsSrcConn)
	err = <-errCh
	return
}

func (r *mitmProxyHandler) relayConnForHTTP(ctx context.Context, srcConn, dstConn net.Conn) (err error) {
	response, err := r.roundTripWithContext(ctx, dstConn)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	response.Write(srcConn)
	return
}

func (r *mitmProxyHandler) roundTripWithContext(ctx context.Context, dstConn net.Conn) (response *http.Response, err error) {
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)
	req := reqCtx.Request
	newCtx := context.WithValue(req.Context(), preboundConnKey, dstConn)
	req = req.WithContext(newCtx)

	// Only one http interceptor will be invoked
	if r.httpInt != nil {
		md.Set(metadata.ConnectionDestinationAddrPort, getAddrPortFromConn(dstConn))
		response, err = r.httpInt(ctx, req, HTTPDelegatedInvokerFunc(r.transport.RoundTrip))
	} else {
		response, err = r.transport.RoundTrip(req)
	}
	return
}

func (r *mitmProxyHandler) serveHTTP2Handler(ctx context.Context, dstConn net.Conn) http.Handler {
	reqCtx, _ := FromRequestContext(ctx)
	md, _ := metadata.FromContext(ctx)
	md.Set(metadata.StreamBody, true)

	// the http.ResponseWriter actually is net/http/h2_bundle.go http2responseWriter
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		md.Set(metadata.RequestReceivedTs, time.Now())

		// Must be set scheme "https" to enable HTTP2 transport!!!
		// This is different from HTTP1 transport!!!
		/*
			net/http/h2_bundle.go (*http2Transport).RoundTripOpt
			switch req.URL.Scheme {
			case "https":
				// Always okay.
			case "http":
				if !t.AllowHTTP && !opt.allowHTTP {
					return nil, errors.New("http2: unencrypted HTTP/2 not enabled")
				}
			default:
				return nil, errors.New("http2: unsupported scheme")
			}
		*/
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}
		ctx = AppendToRequestContext(ctx, reqCtx.Hostport, req)
		response, err := r.roundTripWithContext(ctx, dstConn)
		if err != nil {
			r.handleError(ErrorContext{
				Hostport:   reqCtx.Hostport,
				RemoteAddr: req.RemoteAddr,
				Error:      err,
			})
			return
		}
		body := response.Body
		if body != nil {
			defer body.Close()
		}
		for k, vv := range response.Header {
			for _, v := range vv {
				rw.Header().Add(k, v)
			}
		}
		rw.WriteHeader(response.StatusCode)
		// CAN NOT use response.Write(rw) because it is used for HTTP1
		if body != nil {
			if err = r.forwardStreamBody(rw, body); err != nil {
				r.handleError(ErrorContext{
					Hostport:   reqCtx.Hostport,
					RemoteAddr: req.RemoteAddr,
					Error:      err,
				})
				return
			}
		}

		// Copy trailers for grpc
		for k, vv := range response.Trailer {
			for _, v := range vv {
				rw.Header().Add(http2.TrailerPrefix+k, v)
			}
		}
	})
}

func (r *mitmProxyHandler) forwardStreamBody(rw http.ResponseWriter, body io.Reader) error {
	flusher, ok := rw.(http.Flusher)
	if !ok {
		// This should never happen for http2
		return iocopy.IoCopy(rw, body)
	}
	buffer := acquireHTTP2BodyBuffer()
	defer releaseHTTP2BodyBuffer(buffer)
	for {
		n, err := body.Read(*buffer)
		if n > 0 {
			if _, writeErr := rw.Write((*buffer)[:n]); writeErr != nil {
				return writeErr
			}
			// Flush the response to keep the client happy
			flusher.Flush()
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func getAddrPortFromConn(conn net.Conn) (addrport netip.AddrPort) {
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		addr, _ := netip.AddrFromSlice(tcpAddr.IP)
		addrport = netip.AddrPortFrom(addr, uint16(tcpAddr.Port))
	}
	return
}
