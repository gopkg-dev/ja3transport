package ja3transport_test

import (
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/gopkg-dev/ja3transport"

	"github.com/go-resty/resty/v2"
	utls "github.com/refraction-networking/utls"
)

const (
	defaultJA3       = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,10-5-0-18-13-45-16-17513-23-43-27-35-11-51-65281-21,29-23-24,0"
	defaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
)

func newTestTransport() http.RoundTripper {

	tr, err := ja3transport.NewTransport(
		ja3transport.WithJa3(defaultJA3),
		ja3transport.WithUserAgent(defaultUserAgent),
		ja3transport.WithTLSConfig(&utls.Config{
			InsecureSkipVerify: true,
			OmitEmptyPsk:       true,
		}),
		ja3transport.WithTLSExtensions(&ja3transport.TLSExtensions{
			SupportedSignatureAlgorithms: nil,
			CertCompressionAlgo:          nil,
			RecordSizeLimit:              nil,
			DelegatedCredentials:         nil,
			SupportedVersions:            nil,
			PSKKeyExchangeModes:          nil,
			SignatureAlgorithmsCert:      nil,
			KeyShareCurves:               nil,
			NotUsedGREASE:                false,
		}),
		ja3transport.WithForceHTTP1(false),
		//ja3transport.WithProxy("socks5://user001:pass001@8.8.8.8:8888"),
	)

	if err != nil {
		log.Fatal(err)
	}

	return tr
}

func TestGoResty(t *testing.T) {

	client := resty.NewWithClient(&http.Client{
		Transport: newTestTransport(),
		Timeout:   10 * time.Second,
	})

	client.EnableTrace()
	client.SetDebug(true)
	// 目前无法使用这俩方法,回头 fork 代码改一份
	//client.SetProxy()
	//client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	client.AddRetryCondition(func(resp *resty.Response, err error) bool {
		// network error, auto retry
		if err != nil {
			var urlError *url.Error
			if errors.As(err, &urlError) {
				return true
			}
			var opError *net.OpError
			if errors.As(err, &opError) {
				return true
			}
		}
		return false
	})
	client.SetHeaders(map[string]string{
		"User-Agent": defaultUserAgent,
	})
	rawURL := "https://tls.peet.ws/api/all"
	_, err := client.R().Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
}

func TestClient(t *testing.T) {

	client := &http.Client{
		Transport: newTestTransport(),
		Timeout:   10 * time.Second,
	}

	response, err := client.Get("https://tls.peet.ws/api/all")
	if err != nil {
		t.Fatal(err)
	}

	dumpResponse, err := httputil.DumpResponse(response, true)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%s", string(dumpResponse))
}
