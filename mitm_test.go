package mitmpgo_test

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/josexy/mitmpgo"
	"github.com/josexy/mitmpgo/internal/cert"
	"github.com/josexy/mitmpgo/metadata"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

const (
	certdir        = "/tmp/cert"
	mitmCertPath   = "/tmp/cert/ca.crt"
	mitmKeyPath    = "/tmp/cert/ca.key"
	serverCertPath = "/tmp/cert/server.crt"
	serverKeyPath  = "/tmp/cert/server.key"
)

func startSimpleHttpServer(t *testing.T) func() {
	certificate, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	httpServer := &http.Server{
		Addr:    ":9090",
		Handler: mux,
	}
	httpsServer := &http.Server{
		Addr:    ":9091",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
	}
	h2cServer := &http.Server{
		Addr:    ":9092",
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}

	https1Server := &http.Server{
		Addr:    ":9093",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	go func() {
		t.Log("start HTTP1.1 server on :9090")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
	go func() {
		t.Log("start HTTP2 over TLS server on :9091")
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
	go func() {
		t.Log("start H2C server on :9092")
		if err := h2cServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()
	go func() {
		t.Log("start HTTP1 over TLS server on :9093")
		if err := https1Server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	return func() {
		httpServer.Close()
		httpsServer.Close()
		h2cServer.Close()
		https1Server.Close()
	}
}

func testHTTPRequest(proxyAddr, targetAddr string) (statusCode int, proto string, err error) {
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		Proxy: func(r *http.Request) (*url.URL, error) {
			return url.Parse(proxyAddr)
		},
	}
	if strings.Contains(targetAddr, "https://") {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	client := &http.Client{
		Transport: transport,
	}
	rsp, err := client.Get(targetAddr)
	if err != nil {
		return
	}
	defer rsp.Body.Close()
	return rsp.StatusCode, rsp.Proto, nil
}

func genCACertAndKey() {
	caCert, err := cert.NewCaBuilder().
		Subject(pkix.Name{CommonName: "example.ca.com"}).
		ValidateDays(3650).
		Build()
	if err != nil {
		panic(err)
	}

	keyPem, certPem := caCert.Pem()
	os.Mkdir(certdir, 0755)
	os.WriteFile(mitmCertPath, certPem, 0644)
	os.WriteFile(mitmKeyPath, keyPem, 0644)
}

func genServerCertAndKey() {
	cert, err := cert.NewCertificateBuilder().
		Subject(pkix.Name{CommonName: "localhost"}).
		IPAddresses([]net.IP{net.ParseIP("127.0.0.1")}).
		DNSNames([]string{"localhost"}).
		ValidateDays(365).
		ServerAuth().
		BuildFromCA(nil)
	if err != nil {
		panic(err)
	}

	keyPem, certPem := cert.Pem()
	os.Mkdir(certdir, 0755)
	os.WriteFile(serverCertPath, certPem, 0644)
	os.WriteFile(serverKeyPath, keyPem, 0644)
}

func startmitmpgo(t *testing.T, interceptor mitmpgo.HTTPInterceptorFunc) mitmpgo.MitmProxyHandler {
	handler, err := mitmpgo.NewMitmProxyHandler(
		mitmpgo.WithCACertPath(mitmCertPath),
		mitmpgo.WithCAKeyPath(mitmKeyPath),
		mitmpgo.WithRootCAs(serverCertPath),
	)
	if err != nil {
		panic(err)
	}
	handler.SetErrorHandler(mitmpgo.ErrorHandlerFunc(func(ec mitmpgo.ErrorContext) {
		t.Log(ec.RemoteAddr, ec.Hostport, ec.Error)
	}))
	handler.SetHTTPInterceptor(interceptor)
	return handler
}

func TestMitmProxyHandler(t *testing.T) {
	genCACertAndKey()
	genServerCertAndKey()
	defer os.RemoveAll(certdir)

	handler := startmitmpgo(t, func(hm metadata.HttpMD, hi mitmpgo.HTTPDelegatedInvoker) (*http.Response, error) {
		resp, err := hi.Invoke(hm.Request)
		t.Logf("url: %s, req_proto: %s, rsp_proto: %s", hm.Request.URL, hm.Request.Proto, resp.Proto)
		return resp, err
	})

	proxyAddr := "http://127.0.0.1:10087"

	go func() { http.ListenAndServe(":10087", handler) }()
	closeFunc := startSimpleHttpServer(t)
	time.Sleep(time.Second * 1)

	tests := []struct {
		proto      string
		addr       string
		statusCode int
	}{
		{"HTTP/1.1", "http://127.0.0.1:9090", 200},
		{"HTTP/2.0", "https://127.0.0.1:9091", 200},
		{"HTTP/1.1", "http://127.0.0.1:9092", 200},
		{"HTTP/1.1", "https://127.0.0.1:9093", 200},
	}

	for _, test := range tests {
		statusCode, proto, err := testHTTPRequest(proxyAddr, test.addr)
		if err != nil {
			t.Error(err)
		}
		if statusCode != test.statusCode {
			t.Errorf("statusCode: %d, want: %d", statusCode, test.statusCode)
		}
		if proto != test.proto {
			t.Errorf("proto: %s, want: %s", proto, test.proto)
		}
	}

	closeFunc()
}
