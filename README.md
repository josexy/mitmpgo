# mitmpgo

An easy-use and flexible Man-In-The-Middle (MITM) proxy library for Go that enables transparent interception and inspection of HTTP, HTTPS, HTTP/2, and WebSocket traffic.

## Features

- **Multiple Protocol Support**
  - HTTP/1.1 and HTTP/2 (including h2c - HTTP/2 over cleartext)
  - HTTPS with transparent TLS interception
  - WebSocket and secure WebSocket (WSS)

- **Dual Proxy Modes**
  - HTTP/HTTPS proxy mode
  - SOCKS5 proxy mode

- **Flexible Configuration**
  - Upstream proxy support
  - Custom CA certificates
  - Configurable TLS verification
  - HTTP/2 can be disabled if needed

## Installation

```bash
go get github.com/josexy/mitmpgo
```

## Quick Start

### Basic HTTP Proxy

```go
package main

import (
    "context"
    "fmt"
    "log"
    "net/http"

    "github.com/josexy/mitmpgo"
)

func main() {
    // Create MITM proxy handler
    handler, err := mitmpgo.NewMitmProxyHandler(
        mitmpgo.WithCACertPath("certs/ca.crt"),
        mitmpgo.WithCAKeyPath("certs/ca.key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Start HTTP proxy server
    fmt.Println("Starting proxy on :8080")
    http.ListenAndServe(":8080", handler)
}
```

### With HTTP Interceptor

```go
handler.SetHTTPInterceptor(mitmpgo.HTTPInterceptorFunc(
    func(md metadata.HttpMD, invoker mitmpgo.HTTPDelegatedInvoker) (*http.Response, error) {
        req := md.Request

        // Log request details
        fmt.Printf("→ %s %s\n", req.Method, req.URL)
        fmt.Printf("  Host: %s\n", req.Host)
        fmt.Printf("  Proto: %s\n", req.Proto)

        // Forward the request
        resp, err := invoker.Invoke(req)
        if err != nil {
            return nil, err
        }

        // Log response details
        fmt.Printf("← %s\n", resp.Status)

        return resp, nil
    },
))
```

### With WebSocket Interceptor

```go
handler.SetWebsocketInterceptor(mitmpgo.WebsocketInterceptorFunc(
    func(md metadata.WsMD, buffer *buf.Buffer, invoker mitmpgo.WebsocketDelegatedInvoker) error {
        // Log WebSocket messages
        fmt.Printf("WS [%s] %s: %d bytes\n",
            md.Direction, md.Request.URL, buffer.Len())

        // Forward the message
        return invoker.Invoke(md.MsgType, buffer)
    },
))
```

### SOCKS5 Proxy Mode

```go
func main() {
    handler, err := mitmpgo.NewMitmProxyHandler(
        mitmpgo.WithCACertPath("certs/ca.crt"),
        mitmpgo.WithCAKeyPath("certs/ca.key"),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Listen on TCP port
    ln, err := net.Listen("tcp", ":1080")
    if err != nil {
        log.Fatal(err)
    }
    defer ln.Close()

    fmt.Println("SOCKS5 proxy listening on :1080")

    for {
        conn, err := ln.Accept()
        if err != nil {
            continue
        }

        go func(c net.Conn) {
            defer c.Close()
            handler.ServeSOCKS5(context.Background(), c)
        }(conn)
    }
}
```

## Configuration Options

### Basic Options

```go
// Specify CA certificate and key for TLS interception
mitmpgo.WithCACertPath("path/to/ca.crt")
mitmpgo.WithCAKeyPath("path/to/ca.key")

// Use an upstream proxy
mitmpgo.WithProxy("http://127.0.0.1:8080")

// Disable upstream proxy
mitmpgo.WithDisableProxy()

// Add custom root CA certificates
mitmpgo.WithRootCAs("path/to/root-ca1.crt", "path/to/root-ca2.crt")

// Configure certificate cache pool
mitmpgo.WithCertCachePool(1000, 60000, 3600000)

// Custom dialer with timeout
mitmpgo.WithDialer(&net.Dialer{
    Timeout: 30 * time.Second,
})
```

### Security Options

```go
// Skip SSL verification when connecting to servers (not recommended for production)
mitmpgo.WithSkipVerifySSLFromServer()
```

### Protocol Options

```go
// Disable HTTP/2 support (use HTTP/1.1 only)
mitmpgo.WithDisableHTTP2()
```

### Domain Filtering

```go
// Only intercept specific hosts (supports wildcards)
mitmpgo.WithIncludeHosts("api.example.com", "*.example.org", "example.net")

// Exclude specific hosts from interception (supports wildcards)
mitmpgo.WithExcludeHosts("*.cdn.com", "static.example.com")
```

## Metadata Access

Interceptors receive rich metadata about the connection:

```go
handler.SetHTTPInterceptor(mitmpgo.HTTPInterceptorFunc(
    func(md metadata.HttpMD, invoker mitmpgo.HTTPDelegatedInvoker) (*http.Response, error) {
        // Timing information
        fmt.Printf("Connection established at: %v\n", md.ConnectionEstablishedTs)
        fmt.Printf("SSL handshake duration: %v\n",
            md.SSLHandshakeCompletedTs.Sub(md.ConnectionEstablishedTs))

        // Connection details
        fmt.Printf("Source: %s\n", md.SourceAddr)
        fmt.Printf("Destination: %s\n", md.DestinationAddr)

        // TLS information (if HTTPS)
        if md.TLSState != nil {
            fmt.Printf("ALPN: %s\n", md.TLSState.SelectedALPN)
            fmt.Printf("TLS Version: %d\n", md.TLSState.SelectedTLSVersion)
            fmt.Printf("Cipher Suite: %d\n", md.TLSState.SelectedCipherSuite)
        }

        // Server certificate (if HTTPS)
        if md.ServerCertificate != nil {
            fmt.Printf("Certificate Subject: %v\n", md.ServerCertificate.Subject)
            fmt.Printf("Certificate Issuer: %v\n", md.ServerCertificate.Issuer)
            fmt.Printf("DNS Names: %v\n", md.ServerCertificate.DNSNames)
        }

        return invoker.Invoke(md.Request)
    },
))
```

## Error Handling

```go
handler.SetErrorHandler(mitmpgo.ErrorHandlerFunc(func(ec mitmpgo.ErrorContext) {
    log.Printf("Proxy error - Remote: %s, Host: %s, Error: %v",
        ec.RemoteAddr, ec.Hostport, ec.Error)
}))
```

## Examples

A complete working example is available in `examples/dumper/main.go`. Run it with:

```bash
# HTTP proxy mode
go run examples/dumper/main.go -cacert certs/ca.crt -cakey certs/ca.key -mode http -port 10086

# SOCKS5 proxy mode
go run examples/dumper/main.go -cacert certs/ca.crt -cakey certs/ca.key -mode socks5 -port 10086
```

## Generating CA Certificates

For TLS interception to work, you need a CA certificate. Generate one with OpenSSL:

```bash
chmod +x ./tools/gen_cert.sh
OUTDIR=certs ./tools/gen_cert.sh
```

## License

This project is available under the terms specified in the repository.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
