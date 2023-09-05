package ja3transport

import (
	"golang.org/x/net/proxy"

	utls "github.com/refraction-networking/utls"
)

// Option is config option.
type Option func(*transport) error

func WithJa3(v string) Option {
	return func(c *transport) error {
		c.JA3 = v
		return nil
	}
}

func WithProxy(proxy string) Option {
	return func(c *transport) error {
		dialer, err := newConnectDialer(proxy)
		if err != nil {
			return err
		}
		c.dialer = dialer
		return nil
	}
}

func WithUserAgent(v string) Option {
	return func(c *transport) error {
		c.UserAgent = v
		return nil
	}
}

func WithForceHTTP1(v bool) Option {
	return func(c *transport) error {
		c.forceHTTP1 = v
		return nil
	}
}

func WithTLSConfig(v *utls.Config) Option {
	return func(c *transport) error {
		c.tlsConfig = v
		return nil
	}
}

func WithTLSExtensions(v *TLSExtensions) Option {
	return func(c *transport) error {
		c.tlsExtensions = v
		return nil
	}
}

func WithProxyDialer(v proxy.ContextDialer) Option {
	return func(c *transport) error {
		c.dialer = v
		return nil
	}
}
