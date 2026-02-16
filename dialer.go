// Copyright (c) quickfixengine.org  All rights reserved.
//
// This file may be distributed under the terms of the quickfixengine.org
// license as defined by quickfixengine.org and appearing in the file
// LICENSE included in the packaging of this file.
//
// This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING
// THE WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE.
//
// See http://www.quickfixengine.org/LICENSE for licensing information.
//
// Contact ask@quickfixengine.org if any conditions of this licensing
// are not clear to you.

package quickfix

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"

	"github.com/quickfixgo/quickfix/config"
)

type Dialer interface {
	Dial(ctx context.Context, session *session, attempt int, tlsConfig *tls.Config) (net.Conn, error)
}

type TCPDialer struct {
	ctxDialer proxy.ContextDialer
}

func (d *TCPDialer) Dial(ctx context.Context, session *session, attempt int, tlsConfig *tls.Config) (conn net.Conn, err error) {
	address := session.SocketConnectAddress[attempt%len(session.SocketConnectAddress)]
	session.log.OnEventf("Connecting to: %v", address)

	conn, err = d.ctxDialer.DialContext(ctx, "tcp", address)

	if err != nil {
		return
	} else if tlsConfig != nil {
		// Unless InsecureSkipVerify is true, server name config is required for TLS
		// to verify the received certificate
		if !tlsConfig.InsecureSkipVerify && len(tlsConfig.ServerName) == 0 {
			serverName := address
			if c := strings.LastIndex(serverName, ":"); c > 0 {
				serverName = serverName[:c]
			}
			tlsConfig.ServerName = serverName
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err = tlsConn.Handshake(); err != nil {

			session.log.OnEventf("Failed handshake: %v", err)
			return
		}
		conn = tlsConn
	}

	return
}

type WebsocketDialer struct {
	wsConfig *websocket.Config
}

func (d *WebsocketDialer) Dial(ctx context.Context, session *session, _ int, tlsConfig *tls.Config) (conn net.Conn, err error) {
	session.log.OnEventf("Connecting to: %v", d.wsConfig.Location)

	d.wsConfig.TlsConfig = tlsConfig
	conn, err = d.wsConfig.DialContext(ctx)
	return
}

func loadDialerConfig(settings *SessionSettings) (dialer Dialer, err error) {

	if settings.HasSetting(config.WebsocketLocation) {
		var location string
		location, err = settings.Setting(config.WebsocketLocation)
		if err != nil {
			return nil, err
		}

		var origin string
		origin, err = settings.Setting(config.WebsocketOrigin)
		if err != nil {
			return nil, err
		}

		var wsConfig *websocket.Config
		wsConfig, err = websocket.NewConfig(location, origin)
		if err != nil {
			return nil, err
		}

		dialer = &WebsocketDialer{
			wsConfig: wsConfig,
		}
		return
	}

	stdDialer := &net.Dialer{}
	dialer = &TCPDialer{
		ctxDialer: stdDialer,
	}
	if settings.HasSetting(config.SocketTimeout) {
		timeout, err := settings.DurationSetting(config.SocketTimeout)
		if err != nil {
			timeoutInt, err := settings.IntSetting(config.SocketTimeout)
			if err != nil {
				return nil, err
			}

			stdDialer.Timeout = time.Duration(timeoutInt) * time.Second
		} else {
			stdDialer.Timeout = timeout
		}
	}

	if !settings.HasSetting(config.ProxyType) {
		return
	}

	var proxyType string
	if proxyType, err = settings.Setting(config.ProxyType); err != nil {
		return
	}

	switch proxyType {
	case "socks":
		var proxyHost string
		var proxyPort int
		if proxyHost, err = settings.Setting(config.ProxyHost); err != nil {
			return
		} else if proxyPort, err = settings.IntSetting(config.ProxyPort); err != nil {
			return
		}

		proxyAuth := new(proxy.Auth)
		if settings.HasSetting(config.ProxyUser) {
			if proxyAuth.User, err = settings.Setting(config.ProxyUser); err != nil {
				return
			}
		}
		if settings.HasSetting(config.ProxyPassword) {
			if proxyAuth.Password, err = settings.Setting(config.ProxyPassword); err != nil {
				return
			}
		}

		var proxyDialer proxy.Dialer

		proxyDialer, err = proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", proxyHost, proxyPort), proxyAuth, stdDialer)
		if err != nil {
			return
		}

		if contextDialer, ok := proxyDialer.(proxy.ContextDialer); ok {
			dialer = &TCPDialer{
				ctxDialer: contextDialer,
			}
		} else {
			err = fmt.Errorf("proxy does not support context dialer")
			return
		}

	default:
		err = fmt.Errorf("unsupported proxy type %s", proxyType)
	}

	return
}
