package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// 代理链（中继）支持：client -> 本机中继 -> 住宅代理 -> 目标。
//
// 住宅代理网关经常无法从本机直连，需要先接入本机中继（例如 FlClash 的 mixed
// 端口 7890）再由中继转发。libcurl 用 CURLOPT_PRE_PROXY 表达该语义，但 Go 的
// net/http 没有等价开关，所以这里手写链式拨号：第一跳连中继（SOCKS5 或 HTTP
// CONNECT），第二跳在该隧道上向住宅代理发 CONNECT，最终返回一条已直通目标的
// 连接，同时把 transport.Proxy 置空（CONNECT 已由本拨号器完成）。
const (
	sunnyProxyRelayDefaultURL  = "socks5h://127.0.0.1:7890"
	sunnyProxyRelayEnvKey      = "SUNNY_PROXY_RELAY"
	sunnyProxyRelayDialTimeout = 20 * time.Second
)

var sunnyProxyRelayDisabledValues = map[string]bool{
	"": true, "0": true, "off": true, "none": true, "no": true,
	"false": true, "direct": true, "disabled": true,
}

// defaultSunnyProxyRelayURL 解析本机中继地址；返回空串表示不使用中继。
func defaultSunnyProxyRelayURL() string {
	raw, exists := os.LookupEnv(sunnyProxyRelayEnvKey)
	if !exists {
		return sunnyProxyRelayDefaultURL
	}
	return normalizeSunnyProxyRelayURL(raw)
}

func normalizeSunnyProxyRelayURL(raw string) string {
	value := strings.TrimSpace(raw)
	if sunnyProxyRelayDisabledValues[strings.ToLower(value)] {
		return ""
	}
	return value
}

func sunnyProxyRelayHostPort(target *url.URL) string {
	if target.Port() != "" {
		return target.Host
	}
	switch strings.ToLower(target.Scheme) {
	case "socks5", "socks5h", "socks4", "socks4a":
		return net.JoinHostPort(target.Hostname(), "1080")
	case "https":
		return net.JoinHostPort(target.Hostname(), "443")
	default:
		return net.JoinHostPort(target.Hostname(), "80")
	}
}

// sunnyProxyChainDialContext 构造链式中继拨号器；relay 或 proxy 非法时返回错误，
// 调用方据此回退到直连单代理。
func sunnyProxyChainDialContext(relayURL, proxyURL string) (func(context.Context, string, string) (net.Conn, error), error) {
	relay, err := url.Parse(strings.TrimSpace(relayURL))
	if err != nil || relay.Host == "" {
		return nil, fmt.Errorf("中继地址无效：%s", relayURL)
	}
	proxy, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || proxy.Host == "" {
		return nil, fmt.Errorf("代理地址无效：%s", proxyURL)
	}
	relayAddr := sunnyProxyRelayHostPort(relay)
	proxyAddr := sunnyProxyRelayHostPort(proxy)
	relayScheme := strings.ToLower(relay.Scheme)
	relayUser := relay.User
	proxyUser := proxy.User
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("代理链只支持 tcp，收到 %s", network)
		}
		dialer := &net.Dialer{Timeout: sunnyProxyRelayDialTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", relayAddr)
		if err != nil {
			return nil, fmt.Errorf("连接本机中继 %s 失败：%w", relayAddr, err)
		}
		var tunnel net.Conn
		switch relayScheme {
		case "socks5", "socks5h", "socks4", "socks4a":
			tunnel, err = sunnySocks5Connect(conn, proxyAddr, relayUser)
		default:
			tunnel, err = sunnyHTTPConnect(conn, proxyAddr, relayUser)
		}
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("经中继 %s 连接代理 %s 失败：%w", relayAddr, proxyAddr, err)
		}
		final, err := sunnyHTTPConnect(tunnel, addr, proxyUser)
		if err != nil {
			_ = tunnel.Close()
			return nil, fmt.Errorf("经代理 %s 连接 %s 失败：%w", proxyAddr, addr, err)
		}
		return final, nil
	}, nil
}

// sunnyBufferedConn 把 bufio 已预读的数据保留在读取路径上，避免隧道握手后丢包。
type sunnyBufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *sunnyBufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func sunnyProxyBasicAuth(user *url.Userinfo) string {
	if user == nil {
		return ""
	}
	password, _ := user.Password()
	return base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
}

// sunnyHTTPConnect 在已有连接上向 target 发 CONNECT，成功后返回隧道连接。
func sunnyHTTPConnect(conn net.Conn, target string, user *url.Userinfo) (net.Conn, error) {
	builder := &strings.Builder{}
	builder.WriteString("CONNECT " + target + " HTTP/1.1\r\n")
	builder.WriteString("Host: " + target + "\r\n")
	if credentials := sunnyProxyBasicAuth(user); credentials != "" {
		builder.WriteString("Proxy-Authorization: Basic " + credentials + "\r\n")
	}
	builder.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")
	if _, err := io.WriteString(conn, builder.String()); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	_ = response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("CONNECT %s 返回 HTTP %d", target, response.StatusCode)
	}
	return &sunnyBufferedConn{Conn: conn, reader: reader}, nil
}

// sunnySocks5Connect 在已连通的 socket 上完成 SOCKS5 握手并 CONNECT 到 target。
func sunnySocks5Connect(conn net.Conn, target string, user *url.Userinfo) (net.Conn, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 目标地址无效：%s", target)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("SOCKS5 目标端口无效：%s", target)
	}
	methods := []byte{0x00}
	if user != nil {
		methods = append(methods, 0x02)
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return nil, err
	}
	choice := make([]byte, 2)
	if _, err := io.ReadFull(conn, choice); err != nil {
		return nil, err
	}
	if choice[0] != 0x05 {
		return nil, fmt.Errorf("SOCKS5 版本不匹配（0x%02x）", choice[0])
	}
	switch choice[1] {
	case 0x00:
	case 0x02:
		if user == nil {
			return nil, fmt.Errorf("SOCKS5 中继要求用户名密码认证，但中继地址未包含凭证")
		}
		if err := sunnySocks5Authenticate(conn, user); err != nil {
			return nil, err
		}
	case 0xFF:
		return nil, fmt.Errorf("SOCKS5 中继拒绝了全部认证方式")
	default:
		return nil, fmt.Errorf("SOCKS5 中继返回不支持的认证方式 0x%02x", choice[1])
	}
	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 0x01)
			request = append(request, v4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("SOCKS5 目标域名过长：%s", host)
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	if header[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 连接被拒绝（状态码 0x%02x）", header[1])
	}
	padding := 0
	switch header[3] {
	case 0x01:
		padding = 4
	case 0x04:
		padding = 16
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return nil, err
		}
		padding = int(length[0])
	default:
		return nil, fmt.Errorf("SOCKS5 返回未知地址类型 0x%02x", header[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, padding+2)); err != nil {
		return nil, err
	}
	return conn, nil
}

func sunnySocks5Authenticate(conn net.Conn, user *url.Userinfo) error {
	password, _ := user.Password()
	username := user.Username()
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("SOCKS5 中继凭证过长")
	}
	payload := []byte{0x01, byte(len(username))}
	payload = append(payload, username...)
	payload = append(payload, byte(len(password)))
	payload = append(payload, password...)
	if _, err := conn.Write(payload); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 中继认证失败（状态码 0x%02x）", reply[1])
	}
	return nil
}
