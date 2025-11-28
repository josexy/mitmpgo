package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/josexy/mitmpgo"
	"github.com/josexy/mitmpgo/buf"
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
		mitmpgo.WithChainHTTPInterceptor(httpInterceptor1, httpInterceptor2, httpInterceptor3),
		mitmpgo.WithChainWebsocketInterceptor(websocketInterceptor1, websocketInterceptor2),
	)
	if err != nil {
		panic(err)
	}

	slog.Info("server started")
	http.ListenAndServe(fmt.Sprintf("%s:%d", "127.0.0.1", port), handler)
}

func httpInterceptor1(ctx context.Context, req *http.Request, invoker mitmpgo.HTTPDelegatedInvoker) (*http.Response, error) {
	slog.Debug("httpInterceptor1 before", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String()))
	rsp, err := invoker.Invoke(req)
	if err != nil {
		return rsp, err
	}
	slog.Debug("httpInterceptor1 after", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto))
	return rsp, err
}

func httpInterceptor2(ctx context.Context, req *http.Request, invoker mitmpgo.HTTPDelegatedInvoker) (*http.Response, error) {
	slog.Debug("httpInterceptor2 before", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String()))
	rsp, err := invoker.Invoke(req)
	if err != nil {
		return rsp, err
	}
	slog.Debug("httpInterceptor2 after", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto))
	return rsp, err
}

func httpInterceptor3(ctx context.Context, req *http.Request, invoker mitmpgo.HTTPDelegatedInvoker) (*http.Response, error) {
	slog.Debug("httpInterceptor3 before", slog.String("host", req.Host), slog.String("method", req.Method), slog.String("url", req.URL.String()))
	rsp, err := invoker.Invoke(req)
	if err != nil {
		return rsp, err
	}
	slog.Debug("httpInterceptor3 after", slog.String("status", rsp.Status), slog.String("protocol", rsp.Proto))
	return rsp, err
}

func websocketInterceptor1(ctx context.Context, dir mitmpgo.WSDirection, msgType int, b *buf.Buffer, req *http.Request, invoker mitmpgo.WebsocketDelegatedInvoker) error {
	slog.Debug("websocketInterceptor1 before", slog.String("dir", dir.String()), slog.Int("msgType", msgType), slog.Int("len", b.Len()))
	if dir == mitmpgo.Send {
		b.WriteString("->" + time.Now().Format(time.DateTime))
	}
	err := invoker.Invoke(msgType, b)
	if err != nil {
		return err
	}
	slog.Debug("websocketInterceptor1 after")
	return nil
}

func websocketInterceptor2(ctx context.Context, dir mitmpgo.WSDirection, msgType int, b *buf.Buffer, req *http.Request, invoker mitmpgo.WebsocketDelegatedInvoker) error {
	slog.Debug("websocketInterceptor2 before", slog.String("dir", dir.String()), slog.Int("msgType", msgType), slog.Int("len", b.Len()))
	err := invoker.Invoke(msgType, b)
	if err != nil {
		return err
	}
	slog.Debug("websocketInterceptor2 after")
	return err
}
