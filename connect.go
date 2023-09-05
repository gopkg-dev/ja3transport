package ja3transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"

	utls "github.com/refraction-networking/utls"
)

// connectDialer allows to configure one-time use HTTP CONNECT transport
type proxyDialer struct {
	ProxyURL      url.URL
	DefaultHeader http.Header

	Dialer proxy.ContextDialer // overridden dialer allow to control establishment of TCP connection

	// overridden DialTLS allows user to control establishment of TLS connection
	// MUST return connection with completed Handshake, and NegotiatedProtocol
	DialTLS func(network string, address string) (net.Conn, string, error)

	EnableH2ConnReuse  bool
	cacheH2Mu          sync.Mutex
	cachedH2ClientConn *http2.ClientConn
	cachedH2RawConn    net.Conn
}

const (
	invalidProxy = "invalid proxy `%s`, %s"
)

// newConnectDialer creates a dialer to issue CONNECT requests and tunnel traffic via HTTP/S proxy.
// proxyUrlStr must provide Scheme and Host, may provide credentials and port.
// Example: https://username:password@golang.org:443
func newConnectDialer(proxyURLStr string) (proxy.ContextDialer, error) {
	proxyURL, err := url.Parse(proxyURLStr)
	if err != nil {
		return nil, err
	}
	if proxyURL.Host == "" || proxyURL.Host == "undefined" {
		return nil, fmt.Errorf(invalidProxy, proxyURLStr, "make sure to specify full url like http(s)://username:password@ip:port")
	}
	client := &proxyDialer{
		ProxyURL:          *proxyURL,
		DefaultHeader:     make(http.Header),
		EnableH2ConnReuse: true,
	}
	switch proxyURL.Scheme {
	case "http":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Host, "80")
		}
	case "https":
		if proxyURL.Port() == "" {
			proxyURL.Host = net.JoinHostPort(proxyURL.Host, "443")
		}
	case "socks5":
		var auth *proxy.Auth
		if proxyURL.User != nil {
			if proxyURL.User.Username() != "" {
				username := proxyURL.User.Username()
				password, _ := proxyURL.User.Password()
				auth = &proxy.Auth{User: username, Password: password}
			}
		}
		dialSocksProxy, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, nil)
		if err != nil {
			return nil, fmt.Errorf("error creating socks5 proxy, reason %s", err)
		}
		if contextDialer, ok := dialSocksProxy.(proxy.ContextDialer); ok {
			client.Dialer = contextDialer
		} else {
			return nil, errors.New("failed type assertion to DialContext")
		}
		return client, nil
	case "":
		return nil, fmt.Errorf(invalidProxy, proxyURLStr, "specify scheme explicitly (https://)")
	default:
		return nil, fmt.Errorf(invalidProxy, proxyURLStr, fmt.Sprintf("scheme %s is not supported", proxyURL.Scheme))
	}
	client.Dialer = &net.Dialer{}
	if proxyURL.User != nil {
		if proxyURL.User.Username() != "" {
			username := proxyURL.User.Username()
			password, _ := proxyURL.User.Password()
			auth := username + ":" + password
			basicAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
			client.DefaultHeader.Add("Proxy-Authorization", basicAuth)
		}
	}
	return client, nil
}

func (c *proxyDialer) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// ContextKeyHeader Users of context.WithValue should define their own types for keys
type ContextKeyHeader struct{}

func (c *proxyDialer) connectHTTP1(req *http.Request, conn net.Conn) (net.Conn, error) {
	req.Proto = "HTTP/1.1"
	req.ProtoMajor = 1
	req.ProtoMinor = 1

	err := req.Write(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, errors.New("Proxy responded with non 200 code: " + resp.Status)
	}

	return conn, nil
}

func (c *proxyDialer) connectHTTP2(req *http.Request, conn net.Conn, h2clientConn *http2.ClientConn) (net.Conn, error) {
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	pr, pw := io.Pipe()
	req.Body = pr

	resp, err := h2clientConn.RoundTrip(req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, errors.New("Proxy responded with non 200 code: " + resp.Status)
	}

	return newHTTP2Conn(conn, pw, resp.Body), nil
}

func (c *proxyDialer) initProxyConn(ctx context.Context, network string) (net.Conn, string, error) {
	switch c.ProxyURL.Scheme {
	case "http":
		conn, err := c.Dialer.DialContext(ctx, network, c.ProxyURL.Host)
		if err != nil {
			return nil, "", err
		}
		return conn, "", nil
	case "https":
		if c.DialTLS != nil {
			conn, protocol, err := c.DialTLS(network, c.ProxyURL.Host)
			if err != nil {
				return nil, "", err
			}
			return conn, protocol, nil
		} else {
			conn, err := utls.Dial(network, c.ProxyURL.Host, &utls.Config{
				NextProtos:         []string{"h2", "http/1.1"},
				ServerName:         c.ProxyURL.Hostname(),
				InsecureSkipVerify: true,
			})
			if err != nil {
				return nil, "", err
			}
			err = conn.Handshake()
			if err != nil {
				return nil, "", err
			}
			protocol := conn.ConnectionState().NegotiatedProtocol
			return conn, protocol, nil
		}
	default:
		return nil, "", errors.New("scheme " + c.ProxyURL.Scheme + " is not supported")
	}
}

func (c *proxyDialer) connect(req *http.Request, rawConn net.Conn, negotiatedProtocol string) (net.Conn, error) {

	if negotiatedProtocol == http2.NextProtoTLS {
		//TODO: update this with correct navigator
		t := http2.Transport{}
		if h2clientConn, err := t.NewClientConn(rawConn); err == nil {
			proxyConn, err := c.connectHTTP2(req, rawConn, h2clientConn)
			if err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			if c.EnableH2ConnReuse {
				c.cacheH2Mu.Lock()
				c.cachedH2ClientConn = h2clientConn
				c.cachedH2RawConn = rawConn
				c.cacheH2Mu.Unlock()
			}
			return proxyConn, err
		}
	}

	if negotiatedProtocol == "http/1.1" {
		if _, err := c.connectHTTP1(req, rawConn); err != nil {
			_ = rawConn.Close()
			return nil, err
		}
	}

	_ = rawConn.Close()

	return nil, errors.New("negotiated unsupported application layer protocol: " + negotiatedProtocol)
}

// DialContext ctx.Value will be inspected for optional ContextKeyHeader{} key, with `http.Header` value,
// which will be added to outgoing request headers, overriding any colliding c.DefaultHeader
func (c *proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.ProxyURL.Scheme == "socks5" {
		return c.Dialer.DialContext(ctx, network, address)
	}

	req := (&http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Host: address},
		Header: make(http.Header),
		Host:   address,
	}).WithContext(ctx)

	for k, v := range c.DefaultHeader {
		req.Header[k] = v
	}

	if ctxHeader, ctxHasHeader := ctx.Value(ContextKeyHeader{}).(http.Header); ctxHasHeader {
		for k, v := range ctxHeader {
			req.Header[k] = v
		}
	}

	if c.EnableH2ConnReuse {
		c.cacheH2Mu.Lock()
		unlocked := false
		if c.cachedH2ClientConn != nil && c.cachedH2RawConn != nil {
			if c.cachedH2ClientConn.CanTakeNewRequest() {
				rc := c.cachedH2RawConn
				cc := c.cachedH2ClientConn
				c.cacheH2Mu.Unlock()
				unlocked = true
				proxyConn, err := c.connectHTTP2(req, rc, cc)
				if err == nil {
					return proxyConn, nil
				}
				// else: carry on and try again
			}
		}
		if !unlocked {
			c.cacheH2Mu.Unlock()
		}
	}

	rawConn, negotiatedProtocol, err := c.initProxyConn(ctx, network)
	if err != nil {
		return nil, err
	}

	proxyConn, err := c.connect(req, rawConn, negotiatedProtocol)
	if err != nil {
		return nil, err
	}

	return proxyConn, nil
}
