package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/josexy/mitmpgo"
	"github.com/josexy/mitmpgo/buf"
	"github.com/josexy/mitmpgo/metadata"
)

type chunkBodyReader struct {
	io.ReadCloser
	N int64
}

func newChunkBodyReader(r io.ReadCloser, chunkBodySize int64) *chunkBodyReader {
	return &chunkBodyReader{
		N:          chunkBodySize,
		ReadCloser: r,
	}
}

func (r *chunkBodyReader) Read(p []byte) (n int, err error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.N {
		p = p[0:r.N]
	}
	n, err = r.ReadCloser.Read(p)
	if n > 0 {
		fmt.Printf("--> hex dump(chunk size/data size: %d/%d):\n%s\n", r.N, n, hex.Dump(p[:n]))
	}
	return
}

func main() {
	var caCertPath string
	var caKeyPath string
	var mitmMode string
	var port int
	flag.StringVar(&caCertPath, "cacert", "", "ca cert path")
	flag.StringVar(&caKeyPath, "cakey", "", "ca key path")
	flag.StringVar(&mitmMode, "mode", "http", "http or socks5 mode")
	flag.IntVar(&port, "port", 10086, "proxy port")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	handler, err := mitmpgo.NewMitmProxyHandler(
		mitmpgo.WithCACertPath(caCertPath),
		mitmpgo.WithCAKeyPath(caKeyPath),
		// mitmpgo.WithRootCAs("certs/other-ca.crt"),
		// mitmpgo.WithIncludeHosts("ifconfig.co", "*.example.com", "example.com", "*.bilibili.com"),
		// mitmpgo.WithIncludeHosts("api.bilibili.com"),
		// mitmpgo.WithExcludeHosts("www.baidu.com"),
		// mitmpgo.WithProxy("http://127.0.0.1:7900"),
		// mitmpgo.WithDisableProxy(),
		// mitmpgo.WithDisableHTTP2(),
		// mitmpgo.WithSkipVerifySSLFromServer(),
	)
	if err != nil {
		panic(err)
	}

	handler.SetErrorHandler(mitmpgo.ErrorHandlerFunc(func(ec mitmpgo.ErrorContext) {
		slog.Error("mitm proxy error",
			slog.String("remote_addr", ec.RemoteAddr),
			slog.String("hostport", ec.Hostport),
			slog.String("error", ec.Error.Error()),
		)
	}))

	handler.SetHTTPInterceptor(mitmpgo.HTTPInterceptorFunc(
		func(md metadata.HttpMD, invoker mitmpgo.HTTPDelegatedInvoker) (*http.Response, error) {
			req := md.Request
			slog.Debug("request",
				slog.Bool("stream_body", md.StreamBody),
				slog.String("source", md.SourceAddr.String()),
				slog.String("destination", md.DestinationAddr.String()),
				slog.String("hostport", md.RequestHostport),
				slog.String("host", req.Host),
				slog.String("proto", req.Proto),
				slog.String("method", req.Method),
				slog.Bool("tls", req.TLS != nil),
				slog.String("url", req.URL.String()),
				slog.Any("headers", map[string][]string(req.Header)),
			)

			if md.TLSState != nil {
				slog.Debug("tls state",
					slog.String("server_name", md.TLSState.ServerName),
					slog.String("alpn", strings.Join(md.TLSState.ALPN, ",")),
					slog.String("selected_ciphersuite", tls.CipherSuiteName(md.TLSState.SelectedCipherSuite)),
					slog.String("selected_version", tls.VersionName(md.TLSState.SelectedTLSVersion)),
					slog.String("selected_alpn", md.TLSState.SelectedALPN),
				)
			}
			if md.ServerCertificate != nil {
				slog.Debug("server certificate",
					slog.Int("version", md.ServerCertificate.Version),
					slog.String("not_after", md.ServerCertificate.NotAfter.String()),
					slog.String("not_before", md.ServerCertificate.NotBefore.String()),
					slog.String("subject", md.ServerCertificate.Subject.String()),
					slog.String("issuer", md.ServerCertificate.Issuer.String()),
					slog.String("serial_number", md.ServerCertificate.SerialNumberHex()),
					slog.String("signature_algorithm", md.ServerCertificate.SignatureAlgorithm.String()),
					slog.String("sha1_fingerprint", md.ServerCertificate.Sha1FingerprintHex()),
					slog.String("sha256_fingerprint", md.ServerCertificate.Sha256FingerprintHex()),
					slog.String("dns", strings.Join(md.ServerCertificate.DNSNames, ",")),
					slog.Any("ip", md.ServerCertificate.IPAddresses),
				)
			}

			if md.StreamBody {
				req.Body = newChunkBodyReader(req.Body, 512)
			} else {
				data, _ := httputil.DumpRequest(req, true)
				fmt.Println("request:", string(data))
			}

			rsp, err := invoker.Invoke(req)
			if err != nil {
				return rsp, err
			}

			slog.Debug("response",
				slog.Duration("connection_establishment", time.Since(md.ConnectionEstablishedTs)),
				slog.Duration("ssl_handshake_latency", md.SSLHandshakeCompletedTs.Sub(md.ConnectionEstablishedTs)),
				slog.Duration("request_latency", time.Since(md.RequestProcessedTs)),
				slog.String("status", rsp.Status),
				slog.String("protocol", rsp.Proto),
			)

			if md.StreamBody {
				rsp.Body = newChunkBodyReader(rsp.Body, 512)
			} else {
				data, _ := httputil.DumpResponse(rsp, true)
				fmt.Println("response:", string(data))
			}

			return rsp, err
		}),
	)

	handler.SetWebsocketInterceptor(mitmpgo.WebsocketInterceptorFunc(
		func(md metadata.WsMD, b *buf.Buffer, wdi mitmpgo.WebsocketDelegatedInvoker) error {
			slog.Debug("websocket",
				slog.String("source", md.SourceAddr.String()),
				slog.String("destination", md.DestinationAddr.String()),
				slog.String("hostport", md.RequestHostport),
				slog.String("uri", md.Request.URL.String()),
				slog.String("direction", md.Direction.String()),
				slog.Int("msg_type", md.MsgType),
			)
			if md.TLSState != nil {
				slog.Debug("tls state",
					slog.String("server_name", md.TLSState.ServerName),
					slog.String("alpn", strings.Join(md.TLSState.ALPN, ",")),
					slog.String("selected_ciphersuite", tls.CipherSuiteName(md.TLSState.SelectedCipherSuite)),
					slog.String("selected_version", tls.VersionName(md.TLSState.SelectedTLSVersion)),
					slog.String("selected_alpn", md.TLSState.SelectedALPN),
				)
			}
			if md.ServerCertificate != nil {
				slog.Debug("server certificate",
					slog.Int("version", md.ServerCertificate.Version),
					slog.String("not_after", md.ServerCertificate.NotAfter.String()),
					slog.String("not_before", md.ServerCertificate.NotBefore.String()),
					slog.String("subject", md.ServerCertificate.Subject.String()),
					slog.String("issuer", md.ServerCertificate.Issuer.String()),
					slog.String("serial_number", md.ServerCertificate.SerialNumberHex()),
					slog.String("signature_algorithm", md.ServerCertificate.SignatureAlgorithm.String()),
					slog.String("sha1_fingerprint", md.ServerCertificate.Sha1FingerprintHex()),
					slog.String("sha256_fingerprint", md.ServerCertificate.Sha256FingerprintHex()),
					slog.String("dns", strings.Join(md.ServerCertificate.DNSNames, ",")),
					slog.Any("ip", md.ServerCertificate.IPAddresses),
				)
			}
			// if md.Direction == metadata.Receive {
			// 	b.WriteString(time.Now().String())
			// }
			return wdi.Invoke(md.MsgType, b)
		}),
	)

	listenAddr := fmt.Sprintf("%s:%d", "127.0.0.1", port)
	var closeFn func()
	switch mitmMode {
	case "socks5":
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			panic(err)
		}
		closeFn = func() { ln.Close() }
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					handler.ServeSOCKS5(context.Background(), conn)
				}()
			}
		}()
	default:
		server := &http.Server{
			Addr:    listenAddr,
			Handler: handler,
		}
		closeFn = func() { server.Close() }
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				panic(err)
			}
		}()
	}
	slog.Info("server started")

	inter := make(chan os.Signal, 1)
	signal.Notify(inter, syscall.SIGINT)
	<-inter

	slog.Info("exit")
	closeFn()
	time.Sleep(time.Millisecond * 100)
}
