package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type sunnyRelayRecorder struct {
	mu      sync.Mutex
	targets []string
	auths   []string
}

func (r *sunnyRelayRecorder) record(target, auth string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets = append(r.targets, target)
	r.auths = append(r.auths, auth)
}

func (r *sunnyRelayRecorder) snapshot() ([]string, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.targets...), append([]string(nil), r.auths...)
}

func (r *sunnyRelayRecorder) first() string {
	targets, _ := r.snapshot()
	if len(targets) == 0 {
		return ""
	}
	return targets[0]
}

// startSunnyFakeTarget 起一个仅用于握手的 TCP 目标：先回 "PONG"，随后回显。
func startSunnyFakeTarget(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听假目标失败：%v", err)
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, writeErr := c.Write([]byte("PONG")); writeErr != nil {
					return
				}
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// startSunnyFakeConnectProxy 起一个最小 HTTP CONNECT 代理。
func startSunnyFakeConnectProxy(t *testing.T, recorder *sunnyRelayRecorder) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听假 CONNECT 代理失败：%v", err)
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				request, readErr := http.ReadRequest(reader)
				if readErr != nil {
					return
				}
				recorder.record(request.Host, request.Header.Get("Proxy-Authorization"))
				upstream, dialErr := net.Dial("tcp", request.Host)
				if dialErr != nil {
					_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer upstream.Close()
				if _, writeErr := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); writeErr != nil {
					return
				}
				if reader.Buffered() > 0 {
					if buffered, peekErr := reader.Peek(reader.Buffered()); peekErr == nil {
						_, _ = upstream.Write(buffered)
					}
				}
				go func() { _, _ = io.Copy(upstream, c) }()
				_, _ = io.Copy(c, upstream)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// startSunnyFakeSocks5 起一个最小 SOCKS5 代理（无认证）。
func startSunnyFakeSocks5(t *testing.T, recorder *sunnyRelayRecorder) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听假 SOCKS5 中继失败：%v", err)
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				greeting := make([]byte, 2)
				if _, readErr := io.ReadFull(c, greeting); readErr != nil {
					return
				}
				methods := make([]byte, int(greeting[1]))
				if _, readErr := io.ReadFull(c, methods); readErr != nil {
					return
				}
				if _, writeErr := c.Write([]byte{0x05, 0x00}); writeErr != nil {
					return
				}
				head := make([]byte, 4)
				if _, readErr := io.ReadFull(c, head); readErr != nil {
					return
				}
				var host string
				switch head[3] {
				case 0x01:
					raw := make([]byte, 4)
					if _, readErr := io.ReadFull(c, raw); readErr != nil {
						return
					}
					host = net.IP(raw).String()
				case 0x03:
					length := make([]byte, 1)
					if _, readErr := io.ReadFull(c, length); readErr != nil {
						return
					}
					raw := make([]byte, int(length[0]))
					if _, readErr := io.ReadFull(c, raw); readErr != nil {
						return
					}
					host = string(raw)
				case 0x04:
					raw := make([]byte, 16)
					if _, readErr := io.ReadFull(c, raw); readErr != nil {
						return
					}
					host = net.IP(raw).String()
				default:
					return
				}
				portBytes := make([]byte, 2)
				if _, readErr := io.ReadFull(c, portBytes); readErr != nil {
					return
				}
				target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes))))
				recorder.record(target, "")
				upstream, dialErr := net.Dial("tcp", target)
				if dialErr != nil {
					_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer upstream.Close()
				if _, writeErr := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); writeErr != nil {
					return
				}
				go func() { _, _ = io.Copy(upstream, c) }()
				_, _ = io.Copy(c, upstream)
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func sunnyDialThroughChain(t *testing.T, relayURL, proxyURL, targetAddr string) net.Conn {
	t.Helper()
	dial, err := sunnyProxyChainDialContext(relayURL, proxyURL)
	if err != nil {
		t.Fatalf("构造链式拨号器失败：%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("链式拨号失败：%v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func sunnyAssertHandshake(t *testing.T, conn net.Conn) {
	t.Helper()
	banner := make([]byte, 4)
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("读取目标 banner 失败：%v", err)
	}
	if string(banner) != "PONG" {
		t.Fatalf("目标 banner = %q，期望 PONG", string(banner))
	}
	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatalf("写入目标失败：%v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil {
		t.Fatalf("读取目标回显失败：%v", err)
	}
	if string(echo) != "PING" {
		t.Fatalf("目标回显 = %q，期望 PING", string(echo))
	}
}

func TestSunnyProxyChainDialContextRoutesSocksRelayThenProxy(t *testing.T) {
	target := startSunnyFakeTarget(t)
	proxyLog := &sunnyRelayRecorder{}
	proxy := startSunnyFakeConnectProxy(t, proxyLog)
	relayLog := &sunnyRelayRecorder{}
	relay := startSunnyFakeSocks5(t, relayLog)

	conn := sunnyDialThroughChain(t, "socks5h://"+relay.Addr().String(), "http://"+proxy.Addr().String(), target.Addr().String())
	sunnyAssertHandshake(t, conn)

	if got, want := relayLog.first(), proxy.Addr().String(); got != want {
		t.Errorf("SOCKS5 中继目标 = %q，期望先连代理 %q", got, want)
	}
	if got, want := proxyLog.first(), target.Addr().String(); got != want {
		t.Errorf("住宅代理 CONNECT 目标 = %q，期望最终目标 %q", got, want)
	}
}

func TestSunnyProxyChainDialContextRoutesHTTPRelayWithCredentials(t *testing.T) {
	target := startSunnyFakeTarget(t)
	proxyLog := &sunnyRelayRecorder{}
	proxy := startSunnyFakeConnectProxy(t, proxyLog)
	relayLog := &sunnyRelayRecorder{}
	relay := startSunnyFakeConnectProxy(t, relayLog)

	conn := sunnyDialThroughChain(t, "http://relay-user:relay-pass@"+relay.Addr().String(), "http://proxy-user:proxy-pass@"+proxy.Addr().String(), target.Addr().String())
	sunnyAssertHandshake(t, conn)

	relayTargets, relayAuths := relayLog.snapshot()
	if len(relayTargets) != 1 || relayTargets[0] != proxy.Addr().String() {
		t.Errorf("第一跳 CONNECT 目标 = %v，期望 %q", relayTargets, proxy.Addr().String())
	}
	// 代理处的两跳凭证：第一跳是中继凭证，第二跳是住宅代理凭证。
	_, proxyAuths := proxyLog.snapshot()
	if len(proxyAuths) != 1 {
		t.Fatalf("代理收到 %d 次 CONNECT，期望 1 次", len(proxyAuths))
	}
	if !strings.HasPrefix(relayAuths[0], "Basic ") {
		t.Errorf("中继未收到 Basic 凭证：%q", relayAuths[0])
	}
	if !strings.HasPrefix(proxyAuths[0], "Basic ") {
		t.Errorf("住宅代理未收到 Basic 凭证：%q", proxyAuths[0])
	}
}

func TestSunnyProxyChainDialContextRejectsInvalidInput(t *testing.T) {
	if _, err := sunnyProxyChainDialContext("", "http://proxy.example:8080"); err == nil {
		t.Error("空中继地址应当报错")
	}
	if _, err := sunnyProxyChainDialContext("socks5h://relay.example:1080", ""); err == nil {
		t.Error("空代理地址应当报错")
	}
	dial, err := sunnyProxyChainDialContext("socks5h://relay.example:1080", "http://proxy.example:8080")
	if err != nil {
		t.Fatalf("构造拨号器失败：%v", err)
	}
	if _, err := dial(context.Background(), "udp", "example.com:443"); err == nil {
		t.Error("非 tcp 网络应当报错")
	}
}

func sunnyUnsetRelayEnv(t *testing.T) {
	t.Helper()
	previous, existed := os.LookupEnv(sunnyProxyRelayEnvKey)
	if err := os.Unsetenv(sunnyProxyRelayEnvKey); err != nil {
		t.Fatalf("清除中继环境变量失败：%v", err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(sunnyProxyRelayEnvKey, previous)
			return
		}
		_ = os.Unsetenv(sunnyProxyRelayEnvKey)
	})
}

func TestSunnyProxyRelayURLDefaultsAndDisabling(t *testing.T) {
	// 环境变量完全未设置时才回落到本机默认中继。
	sunnyUnsetRelayEnv(t)
	if got := defaultSunnyProxyRelayURL(); got != sunnyProxyRelayDefaultURL {
		t.Errorf("未设置环境变量时 = %q，期望本地中继 %q", got, sunnyProxyRelayDefaultURL)
	}
	t.Setenv(sunnyProxyRelayEnvKey, "socks5h://relay.example:1080")
	if got := defaultSunnyProxyRelayURL(); got != "socks5h://relay.example:1080" {
		t.Errorf("环境变量覆盖失败：%q", got)
	}
	// 与 Python 侧一致：只要环境变量存在就以其为准，空串即关闭中继。
	for _, disabled := range []string{"", "off", "direct", "none", "0", "disabled"} {
		t.Setenv(sunnyProxyRelayEnvKey, disabled)
		if got := defaultSunnyProxyRelayURL(); got != "" {
			t.Errorf("%q 应关闭中继，实际 %q", disabled, got)
		}
	}
}

func TestSunnyCommerceHTTPClientInstallsRelayChain(t *testing.T) {
	// http.DefaultTransport 自带 DialContext，必须比较函数指针才能证明被替换。
	defaultDial := http.DefaultTransport.(*http.Transport).DialContext
	sameAsDefault := func(dial func(context.Context, string, string) (net.Conn, error)) bool {
		return dial != nil && reflect.ValueOf(dial).Pointer() == reflect.ValueOf(defaultDial).Pointer()
	}

	t.Setenv(sunnyProxyRelayEnvKey, "socks5h://127.0.0.1:1")
	transport, ok := sunnyCommerceHTTPClient("http://proxy.example:8080").Transport.(*http.Transport)
	if !ok {
		t.Fatal("默认传输层不是 *http.Transport")
	}
	if transport.Proxy != nil {
		t.Error("启用中继时不应再由 net/http 直接拨号代理（Proxy 应为 nil）")
	}
	if sameAsDefault(transport.DialContext) {
		t.Error("启用中继时应安装链式 DialContext")
	}

	t.Setenv(sunnyProxyRelayEnvKey, "off")
	directTransport, ok := sunnyCommerceHTTPClient("http://proxy.example:8080").Transport.(*http.Transport)
	if !ok {
		t.Fatal("默认传输层不是 *http.Transport")
	}
	if directTransport.Proxy == nil {
		t.Error("关闭中继时应保持直连单代理行为")
	}
	if !sameAsDefault(directTransport.DialContext) {
		t.Error("关闭中继时不应改动 DialContext")
	}
}
