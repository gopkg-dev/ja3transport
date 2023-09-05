package ja3transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"

	utls "github.com/refraction-networking/utls"
)

const (
	defaultJA3       = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-5-0-18-13-45-16-17513-23-43-27-35-11-51-65281-21,29-23-24,0"
	defaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
)

var errProtocolNegotiated = errors.New("protocol negotiated")

type transport struct {
	sync.Mutex

	JA3       string
	UserAgent string

	cachedConnections map[string]net.Conn
	cachedTransports  map[string]http.RoundTripper

	proxy  string
	dialer proxy.ContextDialer

	tlsConfig     *utls.Config
	tlsExtensions *TLSExtensions
	forceHTTP1    bool
}

func NewTransport(opts ...Option) (http.RoundTripper, error) {

	tr := &transport{
		JA3:               defaultJA3,
		UserAgent:         defaultUserAgent,
		cachedConnections: make(map[string]net.Conn),
		cachedTransports:  make(map[string]http.RoundTripper),
		dialer:            proxy.Direct,
		tlsConfig:         nil,
		tlsExtensions:     &TLSExtensions{},
		forceHTTP1:        false,
	}

	for _, opt := range opts {
		if err := opt(tr); err != nil {
			return nil, err
		}
	}

	if tr.tlsConfig == nil {
		if strings.Index(strings.Split(tr.JA3, ",")[2], "-41") == -1 {
			tr.tlsConfig = &utls.Config{
				InsecureSkipVerify: true,
			}
		} else {
			tr.tlsConfig = &utls.Config{
				InsecureSkipVerify: true,
				SessionTicketKey:   [32]byte{},
				ClientSessionCache: utls.NewLRUClientSessionCache(0),
				OmitEmptyPsk:       true,
			}
		}
	}

	return tr, nil
}

func (rt *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", rt.UserAgent)
	}
	addr := rt.getDialTLSAddr(req)
	if _, ok := rt.cachedTransports[addr]; !ok {
		if err := rt.getTransport(req, addr); err != nil {
			return nil, err
		}
	}
	return rt.cachedTransports[addr].RoundTrip(req)
}

func (rt *transport) getDialTLSAddr(req *http.Request) string {
	host, port, err := net.SplitHostPort(req.URL.Host)
	if err == nil {
		return net.JoinHostPort(host, port)
	}
	return net.JoinHostPort(req.URL.Host, "443") // we can assume port is 443 at this point
}

func (rt *transport) getTransport(req *http.Request, addr string) error {
	if req.URL.Scheme == "http" {
		rt.cachedTransports[addr] = &http.Transport{
			DialContext:       rt.dialer.DialContext,
			DisableKeepAlives: true,
		}
		return nil
	} else if req.URL.Scheme != "https" {
		return fmt.Errorf("unsupported scheme: %s", req.URL.Scheme)
	}

	_, err := rt.dialTLS(context.Background(), "tcp", addr)
	switch {
	case errors.Is(err, errProtocolNegotiated):
	case err == nil:
		// Should never happen.
		panic("dialTLS returned no error when determining cachedTransports")
	default:
		return err
	}

	return nil
}

func (rt *transport) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	rt.Lock()
	defer rt.Unlock()

	// If we have the connection from when we determined the HTTPS
	// cachedTransports to use, return that.
	if conn := rt.cachedConnections[addr]; conn != nil {
		delete(rt.cachedConnections, addr)
		return conn, nil
	}
	rawConn, err := rt.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	var host string
	if host, _, err = net.SplitHostPort(addr); err != nil {
		host = addr
	}

	spec, err := StringToSpec(rt.JA3, rt.UserAgent, rt.tlsExtensions, rt.forceHTTP1)
	if err != nil {
		return nil, err
	}

	rt.tlsConfig.ServerName = host
	uConn := utls.UClient(rawConn, rt.tlsConfig.Clone(), utls.HelloCustom)
	if err = uConn.ApplyPreset(spec); err != nil {
		return nil, fmt.Errorf("uConn.ApplyPreset() error: %+v", err)
	}

	if err = uConn.HandshakeContext(ctx); err != nil {
		_ = uConn.Close()
		if err.Error() == "tls: CurvePreferences includes unsupported curve" {
			//fix this
			return nil, fmt.Errorf("conn.Handshake() error for tls 1.3 (please retry request): %+v", err)
		}
		return nil, fmt.Errorf("uConn.Handshake() error: %+v", err)
	}

	if rt.cachedTransports[addr] != nil {
		return uConn, nil
	}

	// No http.Transport constructed yet, create one based on the results of ALPN.
	switch uConn.ConnectionState().NegotiatedProtocol {
	case http2.NextProtoTLS:
		rt.cachedTransports[addr] = &http2.Transport{
			DialTLSContext:            rt.dialTLSHTTP2,
			MaxDecoderHeaderTableSize: 1 << 16, // this line added
		}
	default:
		// Assume the remote peer is speaking HTTP 1.x + TLS.
		rt.cachedTransports[addr] = &http.Transport{
			DialTLSContext: rt.dialTLS,
		}
	}

	// Stash the connection just established for use servicing the
	// actual request (should be near-immediate).
	rt.cachedConnections[addr] = uConn

	return nil, errProtocolNegotiated
}

func (rt *transport) dialTLSHTTP2(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
	return rt.dialTLS(ctx, network, addr)
}
