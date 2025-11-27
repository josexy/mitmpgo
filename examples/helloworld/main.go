package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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

	handler.SetHTTPInterceptor(mitmpgo.HTTPInterceptorFunc(
		func(md metadata.HttpMD, invoker mitmpgo.HTTPDelegatedInvoker) (*http.Response, error) {
			req := md.Request
			slog.Debug("request", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String()))

			rsp, err := invoker.Invoke(req)
			if err != nil {
				return rsp, err
			}

			slog.Debug("response", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto))
			return rsp, err
		}),
	)

	slog.Info("server started")
	go func() {
		http.ListenAndServe(fmt.Sprintf("%s:%d", "127.0.0.1", port), handler)
	}()

	inter := make(chan os.Signal, 1)
	signal.Notify(inter, syscall.SIGINT)
	<-inter

	slog.Info("exit")
}
