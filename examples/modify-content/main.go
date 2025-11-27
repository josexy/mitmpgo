package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/josexy/mitmpgo"
	"github.com/josexy/mitmpgo/metadata"
)

func main() {
	var caCertPath string
	var caKeyPath string
	var port int
	flag.StringVar(&caCertPath, "cacert", "", "ca cert path")
	flag.StringVar(&caKeyPath, "cakey", "", "ca key path")
	flag.IntVar(&port, "port", 10086, "proxy port")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	handler, err := mitmpgo.NewMitmProxyHandler(
		mitmpgo.WithCACertPath(caCertPath),
		mitmpgo.WithCAKeyPath(caKeyPath),
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
			req.Header.Add("X-MITMPGO-REQ-HEADER", "MITMPGO")

			rsp, err := invoker.Invoke(req)
			if err != nil {
				return rsp, err
			}

			slog.Debug("HTTP",
				slog.Group("request", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String())),
				slog.Group("response", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto)),
			)

			rsp.Header.Add("X-MITMPGO-RSP-HEADER", "MITMPGO")
			rsp.Body.Close()
			rsp.Body = io.NopCloser(strings.NewReader("hello!"))
			return rsp, err
		}),
	)

	slog.Info("server started")
	http.ListenAndServe(fmt.Sprintf("%s:%d", "127.0.0.1", port), handler)
}
