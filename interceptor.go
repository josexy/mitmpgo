package mitmpgo

import (
	"net/http"

	"github.com/josexy/mitmpgo/buf"
	"github.com/josexy/mitmpgo/metadata"
)

type (
	HTTPDelegatedInvoker interface {
		Invoke(request *http.Request) (*http.Response, error)
	}

	WebsocketDelegatedInvoker interface {
		Invoke(msgType int, dataPtr *buf.Buffer) error
	}

	HTTPInterceptor interface {
		InvokeInterceptor(metadata.HttpMD, HTTPDelegatedInvoker) (*http.Response, error)
	}

	WebsocketInterceptor interface {
		InvokeInterceptor(metadata.WsMD, *buf.Buffer, WebsocketDelegatedInvoker) error
	}
)

type (
	HTTPDelegatedInvokerFunc      func(*http.Request) (*http.Response, error)
	WebsocketDelegatedInvokerFunc func(int, *buf.Buffer) error

	HTTPInterceptorFunc      func(metadata.HttpMD, HTTPDelegatedInvoker) (*http.Response, error)
	WebsocketInterceptorFunc func(metadata.WsMD, *buf.Buffer, WebsocketDelegatedInvoker) error
)

func (f HTTPDelegatedInvokerFunc) Invoke(r *http.Request) (*http.Response, error) { return f(r) }
func (f WebsocketDelegatedInvokerFunc) Invoke(t int, data *buf.Buffer) error      { return f(t, data) }

func (f HTTPInterceptorFunc) InvokeInterceptor(md metadata.HttpMD, invoker HTTPDelegatedInvoker) (*http.Response, error) {
	defer func() { recover() }() // ignore panic
	return f(md, invoker)
}

func (f WebsocketInterceptorFunc) InvokeInterceptor(md metadata.WsMD, data *buf.Buffer, invoker WebsocketDelegatedInvoker) error {
	defer func() { recover() }() // ignore panic
	return f(md, data, invoker)
}

func wrapperInvoker(fn func(messageType int, data []byte) error) WebsocketDelegatedInvokerFunc {
	return func(i int, b *buf.Buffer) error {
		return fn(i, b.Bytes())
	}
}
