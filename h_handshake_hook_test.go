package htls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOnClientHelloMessage(t *testing.T) {
	cert, err := LoadX509KeyPair("testdata/rsa_cert.pem", "testdata/rsa_key.pem")
	testCheckError(t, err)

	chHook := func(hello *ClientHelloMessage) error {
		secret := make([]byte, 32)
		secret[0] = 0xFF
		if bytes.Equal(hello.Random, secret) {
			hello.ALPNProto = []string{"http/1.1"}
		}
		return nil
	}
	serverCfg := &Config{
		Certificates:         []Certificate{cert},
		NextProtos:           []string{"h2", "http/1.1"},
		OnClientHelloMessage: chHook,
	}
	serverCfg.Random = make([]byte, 32)
	serverCfg.Random[0] = 0xFE
	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg.Clone())
	testCheckError(t, err)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			c := conn.(*Conn)
			err = c.Handshake()
			testCheckError(t, err)

			err = conn.Close()
			testCheckError(t, err)
		}
	}()

	shHook := func(hello *ServerHelloMessage) error {
		secret := make([]byte, 32)
		secret[0] = 0xFE
		if !bytes.Equal(hello.Random, secret) {
			return errors.New("invalid server random")
		}
		return nil
	}

	clientCfg := &Config{
		NextProtos:           []string{"h2", "http/1.1"},
		RootCAs:              x509.NewCertPool(),
		OnServerHelloMessage: shHook,
	}
	clientCfg.RootCAs.AddCert(testLoadCertificate(t, "rsa_cert.pem"))
	clientCfg.Random = make([]byte, 32)
	clientCfg.Random[0] = 0xFF

	conn, err := Dial("tcp", listener.Addr().String(), clientCfg.Clone())
	testCheckError(t, err)

	err = conn.Handshake()
	testCheckError(t, err)

	state := conn.ConnectionState()
	if state.Version != VersionTLS13 {
		t.Fatal("Version should be 1.3")
	}
	if state.NegotiatedProtocol != "http/1.1" {
		t.Fatal("NegotiatedProtocol should be http/1.1")
	}

	err = conn.Close()
	testCheckError(t, err)

	err = listener.Close()
	testCheckError(t, err)
}

func TestOnServerHelloMessage(t *testing.T) {
	cert, err := LoadX509KeyPair("testdata/ecdsa_cert.pem", "testdata/ecdsa_key.pem")
	testCheckError(t, err)

	chHook := func(hello *ClientHelloMessage) error {
		secret := make([]byte, 32)
		secret[0] = 0xFF
		if !bytes.Equal(hello.Random, secret) {
			return errors.New("invalid client random")
		}
		return nil
	}
	serverCfg := &Config{
		MaxVersion:           tls.VersionTLS12,
		Certificates:         []Certificate{cert},
		NextProtos:           []string{"h2", "http/1.1"},
		OnClientHelloMessage: chHook,
	}
	serverCfg.Random = make([]byte, 32)
	serverCfg.Random[0] = 0xFE
	listener, err := Listen("tcp", "127.0.0.1:0", serverCfg.Clone())
	testCheckError(t, err)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			c := conn.(*Conn)
			err = c.Handshake()
			testCheckError(t, err)

			err = conn.Close()
			testCheckError(t, err)
		}
	}()

	shHook := func(hello *ServerHelloMessage) error {
		secret := make([]byte, 32)
		secret[0] = 0xFE
		if !bytes.Equal(hello.Random, secret) {
			return errors.New("invalid server random")
		}
		return nil
	}
	clientCfg := &Config{
		MaxVersion:           tls.VersionTLS12,
		NextProtos:           []string{"h2", "http/1.1"},
		RootCAs:              x509.NewCertPool(),
		OnServerHelloMessage: shHook,
	}
	clientCfg.RootCAs.AddCert(testLoadCertificate(t, "ecdsa_cert.pem"))
	clientCfg.Random = make([]byte, 32)
	clientCfg.Random[0] = 0xFF

	conn, err := Dial("tcp", listener.Addr().String(), clientCfg.Clone())
	testCheckError(t, err)

	err = conn.Handshake()
	testCheckError(t, err)

	state := conn.ConnectionState()
	if state.Version != VersionTLS12 {
		t.Fatal("Version should be 1.2")
	}
	if state.NegotiatedProtocol != "h2" {
		t.Fatal("NegotiatedProtocol should be h2")
	}

	err = conn.Close()
	testCheckError(t, err)

	err = listener.Close()
	testCheckError(t, err)
}

func testLoadCertificate(t *testing.T, name string) *x509.Certificate {
	data, err := os.ReadFile(filepath.Join("testdata", name))
	testCheckError(t, err)
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("invalid PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	testCheckError(t, err)
	return cert
}

func testCheckError(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}
