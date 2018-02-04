package tlsmuxd

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

type ProxyConfig struct {
	Email    string `json:"email"`
	CacheDir string `json:"cacheDir"`
	Hosts    map[string][]struct {
		Name string `json:"name"`
		Addr string `json:"addr"`
	} `json:"hosts"`
	Logger *zap.Logger
}

type host struct {
	protos map[string]*backend
	config *tls.Config
}

type Proxy struct {
	hosts   map[string]*host
	manager *autocert.Manager
	config  *tls.Config
	logger  *zap.Logger
}

func NewProxy(pc *ProxyConfig) (*Proxy, error) {
	if pc.CacheDir == "" {
		return nil, errors.New("empty or missing cacheDir")
	}
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(pc.CacheDir),
		Client: &acme.Client{
			HTTPClient: &http.Client{
				Timeout: time.Second * 30,
			},
		},
		Email: pc.Email,
	}
	p := &Proxy{
		hosts:   make(map[string]*host),
		manager: m,
		config: &tls.Config{
			// See golang/go#12895 for why.
			PreferServerCipherSuites: true,
			GetCertificate:           m.GetCertificate,
		},
		logger: pc.Logger,
	}

	keys := make([][32]byte, 1, 96)
	if _, err := rand.Read(keys[0][:]); err != nil {
		return nil, errors.Errorf("session ticket key generation failed: %v", err)
	}
	p.config.SetSessionTicketKeys(keys)
	go p.rotateSessionTicketKeys(keys)
	p.config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if h, ok := p.hosts[hello.ServerName]; ok {
			return h.config, nil
		}
		return p.config, nil
	}

	var hostnameList []string
	for hostname, protos := range pc.Hosts {
		if hostname == "" {
			return nil, errors.New("empty key in hosts")
		}
		hostnameList = append(hostnameList, hostname)
		if len(protos) == 0 {
			return nil, errors.Errorf("hosts.%s is missing protocols", hostname)
		}
		h := &host{
			protos: make(map[string]*backend),
			config: p.config.Clone(),
		}
		for i, proto := range protos {
			if proto.Name != "" {
				h.config.NextProtos = append(h.config.NextProtos, proto.Name)
			}
			if proto.Addr == "" {
				return nil, errors.Errorf("hosts.%s[%d].addr is empty", hostname, i)
			}
			logPrefix := fmt.Sprintf("%s[%s]", hostname, proto.Name)
			h.protos[proto.Name] = &backend{
				addr:   proto.Addr,
				logger: pc.Logger.Named(logPrefix),
			}
		}
		p.hosts[hostname] = h
	}
	p.manager.HostPolicy = autocert.HostWhitelist(hostnameList...)

	return p, nil
}

const (
	httpBindAddr  = ":http"
	httpsBindAddr = ":https"
)

func (p *Proxy) ListenAndServe() error {
	errc := make(chan error)
	go errFn(errc, p.listenAndServeHTTP)
	go errFn(errc, p.listenAndServeTLS)
	return <-errc
}

func errFn(errc chan<- error, errFn func() error) {
	err := errFn()
	select {
	case errc <- err:
	default:
	}
}

func (p *Proxy) listenAndServeHTTP() error {
	httpRedirector := func(w http.ResponseWriter, r *http.Request) {
		u := *r.URL
		u.Scheme = "https"
		u.Host = r.Host
		http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
	}

	s := http.Server{
		Addr:        httpBindAddr,
		Handler:     p.manager.HTTPHandler(http.HandlerFunc(httpRedirector)),
		ReadTimeout: time.Second * 15,
		ErrorLog:    zap.NewStdLog(p.logger),
	}

	p.logger.Info("serving HTTP",
		zap.String("bind_addr", httpBindAddr),
	)

	err := s.ListenAndServe()
	return errors.Wrap(err, "failed to serve HTTP")
}

func (p *Proxy) listenAndServeTLS() error {
	l, err := net.Listen("tcp", httpsBindAddr)
	if err != nil {
		return errors.Wrap(err, "failed to listen on :https")
	}
	p.logger.Info("serving TLS",
		zap.String("bind_addr", httpsBindAddr),
	)
	return p.serve(tcpKeepAliveListener{l.(*net.TCPListener)})
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (l tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := l.AcceptTCP()
	if err != nil {
		return nil, err
	}
	err = tc.SetKeepAlive(true)
	if err != nil {
		return nil, err
	}
	err = tc.SetKeepAlivePeriod(time.Minute)
	return tc, err
}

func (p *Proxy) serve(l net.Listener) error {
	defer l.Close()
	var delay time.Duration
	for {
		c, err := l.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else {
					delay *= 2
					if delay > time.Second {
						delay = time.Second
					}
				}
				p.logger.Info("temp error on listener accept",
					zap.Duration("retry_delay", delay),
					zap.Error(err),
				)
				time.Sleep(delay)
				continue
			}
			return err
		}
		delay = 0
		go p.handle(c)
	}
}

func (p *Proxy) rotateSessionTicketKeys(keys [][32]byte) {
	for {
		time.Sleep(1 * time.Hour)
		if len(keys) < cap(keys) {
			keys = keys[:len(keys)+1]
		}
		copy(keys[1:], keys)
		if _, err := rand.Read(keys[0][:]); err != nil {
			p.logger.Fatal("error generating session ticket key",
				zap.Error(err),
			)
		}
		p.config.SetSessionTicketKeys(keys)
	}
}

func (p *Proxy) handle(c net.Conn) {
	p.logger.Info("accepted connection",
		zap.Stringer("remote_addr", c.RemoteAddr()),
	)
	defer p.logger.Info("disconnected connection",
		zap.Stringer("remote_addr", c.RemoteAddr()),
	)
	defer c.Close()

	tlc := tls.Server(c, p.config)
	if err := tlc.Handshake(); err != nil {
		p.logger.Error("TLS handshake error",
			zap.Stringer("remote_addr", c.RemoteAddr()),
			zap.Error(err),
		)
		// Some old code here I need to investigate.
		// TODO should the TLS library handle prefix?
		//log.Printf("TLS handshake error from %v: %v", c.RemoteAddr(), err)
		return
	}
	cs := tlc.ConnectionState()
	host, ok := p.hosts[cs.ServerName]
	if ok {
		b, ok := host.protos[cs.NegotiatedProtocol]
		if !ok {
			b, ok = host.protos[""]
			if !ok {
				return
			}
		}
		b.handle(tlc)
	}
}

type backend struct {
	addr   string
	logger *zap.Logger
}

var dialer = &net.Dialer{
	Timeout:   3 * time.Second,
	KeepAlive: time.Minute,
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 1<<16)
	},
}

func (b *backend) handle(tlc *tls.Conn) {
	b.logger.Info("accepted connection",
		zap.Stringer("remote_addr", tlc.RemoteAddr()),
	)
	c2, err := dialer.Dial("tcp", b.addr)
	if err != nil {
		b.logger.Error("failed to dial backend",
			zap.String("addr", b.addr),
		)
		return
	}
	defer c2.Close()
	errc := make(chan error, 2)
	cp := func(w io.Writer, r io.Reader) {
		buf := bufferPool.Get().([]byte)
		_, err := io.CopyBuffer(w, r, buf)
		errc <- err
		bufferPool.Put(buf)
	}
	go cp(struct{ io.Writer }{c2}, tlc)
	go cp(tlc, struct{ io.Reader }{c2})
	err = <-errc
	if err != nil {
		b.logger.Error("copying between two connections failed",
			zap.Stringer("remote_addr", tlc.RemoteAddr()),
			zap.Error(err),
		)
	}
}
