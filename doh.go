package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	RequestTimeout = 20 * time.Second
	MaxLatency     = 1000000
)

// DoHProxyClient handles DNS over HTTPS requests
type DoHProxyClient struct {
	data      []byte
	addr      *net.UDPAddr
	conn      *net.UDPConn
	dns       *DNSMessage
	qdomain   string
	proxy     map[string]string
	activeTasks *sync.Map
}

// NewDoHProxyClient creates a new DoH proxy client
func NewDoHProxyClient(data []byte, addr *net.UDPAddr, conn *net.UDPConn, activeTasks *sync.Map) (*DoHProxyClient, error) {
	dns, err := NewDNSMessage(data, false)
	if err != nil {
		return nil, fmt.Errorf("invalid DNS message: %w", err)
	}
	
	return &DoHProxyClient{
		data:      data,
		addr:      addr,
		conn:      conn,
		dns:       dns,
		qdomain:   dns.GetDomain(),
		activeTasks: activeTasks,
	}, nil
}

// Query processes the DNS query
func (c *DoHProxyClient) Query(ctx context.Context) error {
	dohServers, proxy := c.getServersAndProxy(c.qdomain)
	c.proxy = proxy
	
	// Check for unsupported query types
	if c.dns.GetQType() != QTypeA && c.dns.GetQType() != QTypeAAAA {
		return c.queryDoHServers(ctx, c.qdomain, dohServers)
	}
	
	// Check cache
	value, cacheHit, ttlValid := c.cacheQuery()
	
	if cacheHit {
		if item, exists := CacheDB.Get(c.qdomain); exists {
			ttl, _ := item["ttl"].(float64)
			response := c.dns.BuildResponse(value, int64(ttl))
			c.conn.WriteToUDP(response, c.addr)
			
			if !ttlValid {
				// Refresh cache in background
				go c.queryDoHServers(context.Background(), c.qdomain, dohServers)
			}
		}
		return nil
	}
	
	// Check negative cache
	if item, exists := NegativeCache.Get(c.qdomain); exists {
		expireTime, _ := item["expire"].(float64)
		if time.Now().Unix() < int64(expireTime) {
			response := c.dns.BuildErrorResponse()
			c.conn.WriteToUDP(response, c.addr)
			return nil
		}
	}
	
	// Bootstrap for DoH hostnames
	dohHostnames := Cfg.GetDOHHostnames()
	if dohHostnames[c.qdomain] {
		c.bootstrap(c.qdomain)
		return nil
	}
	
	return c.queryDoHServers(ctx, c.qdomain, dohServers)
}

func (c *DoHProxyClient) getServersAndProxy(domain string) ([]string, map[string]string) {
	if !Cfg.Proxy.EnableProxy {
		return Cfg.DOHServers.DirectServers, nil
	}
	
	if TrafficClassifier.Contains(domain) {
		return Cfg.DOHServers.ProxyServers, Cfg.GetProxies()
	}
	
	return Cfg.DOHServers.DirectServers, nil
}

func (c *DoHProxyClient) queryDoHServers(ctx context.Context, domain string, dohServers []string) error {
	type result struct {
		data []byte
		err  error
	}
	
	results := make(chan result, len(dohServers))
	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()
	
	for _, server := range dohServers {
		go func(server string) {
			data, err := c.queryDoH(ctx, domain, server)
			results <- result{data: data, err: err}
		}(server)
	}
	
	firstResponse := true
	allRecords := make([]RRRecord, 0)
	
	for i := 0; i < len(dohServers); i++ {
		select {
		case res := <-results:
			if res.err != nil {
				continue
			}
			
			if firstResponse {
				c.conn.WriteToUDP(res.data, c.addr)
				firstResponse = false
			}
			
			dns, err := NewDNSMessage(res.data, true)
			if err == nil {
				allRecords = append(allRecords, dns.GetRRRecords()...)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	
	c.saveNegativeCache(allRecords)
	c.saveCache(domain, allRecords)
	
	return nil
}

func (c *DoHProxyClient) queryDoH(ctx context.Context, domain, dohServer string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", dohServer, bytes.NewReader(c.data))
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	
	client := &http.Client{
		Timeout: RequestTimeout,
	}
	
	// Configure proxy if needed
	if len(c.proxy) > 0 {
		proxyURL, err := url.Parse(c.proxy["https"])
		if err == nil {
			client.Transport = &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			}
		}
	}
	
	resp, err := client.Do(req)
	if err != nil {
		QueryLog.Errorf("DoH query error: %s -> %s, %v", domain, dohServer, err)
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", resp.StatusCode)
	}
	
	return io.ReadAll(resp.Body)
}

func (c *DoHProxyClient) bootstrap(dohHostname string) {
	if isIP(dohHostname) {
		return
	}
	
	queryMsg := BuildQuery(dohHostname)
	udpResponse := c.queryUDP(Cfg.DOHServers.BootstrapServer, queryMsg)
	
	dns, err := NewDNSMessage(udpResponse, true)
	if err != nil {
		QueryLog.Errorf("Bootstrap query error: %s", dohHostname)
		return
	}
	
	c.saveCache(dohHostname, dns.GetRRRecords())
	if len(dns.GetRRRecords()) == 0 {
		QueryLog.Errorf("Bootstrap query returned no records: %s", dohHostname)
	}
}

func (c *DoHProxyClient) queryUDP(server string, queryMsg []byte) []byte {
	conn, err := net.DialTimeout("udp", server+":53", 5*time.Second)
	if err != nil {
		return []byte{}
	}
	defer conn.Close()
	
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	
	_, err = conn.Write(queryMsg)
	if err != nil {
		return []byte{}
	}
	
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return []byte{}
	}
	
	return buf[:n]
}

func (c *DoHProxyClient) cacheQuery() (string, bool, bool) {
	item, exists := CacheDB.Get(c.qdomain)
	if !exists {
		proxyStr := "false"
		if len(c.proxy) > 0 {
			proxyStr = "true"
		}
		QueryLog.Infof("Cache miss: %s, proxy: %s", c.qdomain, proxyStr)
		return "", false, true
	}
	
	keyName := QTypeMapping[int(c.dns.GetQType())]
	value, exists := item[keyName].(string)
	if !exists || value == "" {
		return "", false, true
	}
	
	ttlExpire, _ := item["ttl"].(float64)
	
	proxyStr := "false"
	if len(c.proxy) > 0 {
		proxyStr = "true"
	}
	
	ttlValid := time.Now().Unix() < int64(ttlExpire)
	QueryLog.Infof("Cache hit: %s -> %s, ttl_valid: %v, proxy: %s", c.qdomain, value, ttlValid, proxyStr)
	
	return value, true, ttlValid
}

func (c *DoHProxyClient) saveCache(domain string, records []RRRecord) {
	var ttl uint32
	cnames := make(map[string]bool)
	ip4List := make([]string, 0)
	ip6List := make([]string, 0)
	
	for _, record := range records {
		if record.Name == "" || record.RData == "" {
			continue
		}
		
		switch record.Type {
		case QTypeA:
			ttl = record.TTL
			ip4List = append(ip4List, record.RData)
		case QTypeAAAA:
			ip6List = append(ip6List, record.RData)
		case QTypeCNAME:
			cnames[record.RData] = true
		}
	}
	
	expireTime := time.Now().Unix() + int64(ttl)
	
	if len(ip4List) > 0 {
		fastIP, expTime := c.cacheFastIP(domain, ttl, ip4List)
		
		if len(cnames) > 0 {
			c.saveCNAMEIP(cnames, fastIP, expTime)
		}
	}
	
	if len(ip6List) > 0 {
		c.saveIP6(domain, ip6List[0], expireTime)
	}
}

func (c *DoHProxyClient) cacheFastIP(domain string, ttl uint32, ipList []string) (string, int64) {
	expireTime := time.Now().Unix() + int64(ttl)
	
	if len(ipList) == 1 {
		ip := ipList[0]
		CacheDB.Set(domain, map[string]interface{}{
			"ip":  ip,
			"ttl": float64(expireTime),
		})
		QueryLog.Infof("Cache save: %s -> %s", domain, ip)
		return ip, expireTime
	}
	
	fastIP := c.getFastIP(ipList)
	CacheDB.Set(domain, map[string]interface{}{
		"ip":  fastIP,
		"ttl": float64(expireTime),
	})
	
	fastTag := "[fast]"
	if len(c.proxy) > 0 {
		fastTag = ""
	}
	QueryLog.Infof("Cache save: %s -> %s%s", domain, fastIP, fastTag)
	
	return fastIP, expireTime
}

func (c *DoHProxyClient) saveCNAMEIP(cnames map[string]bool, ip string, ttlExpire int64) {
	for cname := range cnames {
		CacheDB.Set(cname, map[string]interface{}{
			"ip":  ip,
			"ttl": float64(ttlExpire),
		})
		QueryLog.Infof("Cache save: %s -> %s", cname, ip)
	}
}

func (c *DoHProxyClient) saveIP6(domain, ip6 string, ttlExpire int64) {
	CacheDB.Set(domain, map[string]interface{}{
		"ipv6": ip6,
		"ttl":  float64(ttlExpire),
	})
	QueryLog.Infof("Cache save: %s -> %s", domain, ip6)
}

func (c *DoHProxyClient) saveNegativeCache(records []RRRecord) {
	if !c.dns.IsNXDomain() {
		return
	}
	
	for _, record := range records {
		if record.Type != QTypeSOA || record.Name == "" {
			continue
		}
		
		ttlExpire := time.Now().Unix() + MinimumTTL
		NegativeCache.Set(record.Name, map[string]interface{}{
			"expire": float64(ttlExpire),
		})
	}
}

func (c *DoHProxyClient) getFastIP(ipList []string) string {
	if len(c.proxy) > 0 {
		return ipList[0]
	}
	
	lowestLatency := MaxLatency
	fastIP := ipList[0]
	
	for _, ip := range ipList {
		latency := tcpPingLatency(ip, 443, 3*time.Second)
		if latency < lowestLatency {
			fastIP = ip
			lowestLatency = latency
		}
	}
	
	return fastIP
}

func tcpPingLatency(host string, port int, timeout time.Duration) int {
	start := time.Now()
	
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return MaxLatency
	}
	defer conn.Close()
	
	elapsed := time.Since(start)
	return int(elapsed.Milliseconds())
}

func isIP(domain string) bool {
	return net.ParseIP(domain) != nil
}

// DNSServer represents the DNS server
type DNSServer struct {
	conn        *net.UDPConn
	activeTasks *sync.Map
}

// NewDNSServer creates a new DNS server
func NewDNSServer() (*DNSServer, error) {
	addr := net.UDPAddr{
		Port: Cfg.DNS.Port,
		IP:   net.ParseIP(Cfg.DNS.Host),
	}
	
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, fmt.Errorf("failed to start DNS server: %w", err)
	}
	
	return &DNSServer{
		conn:        conn,
		activeTasks: &sync.Map{},
	}, nil
}

// Start starts the DNS server
func (s *DNSServer) Start(ctx context.Context) error {
	MainLog.Infof("DNS Server started on %s:%d", Cfg.DNS.Host, Cfg.DNS.Port)
	
	// Start periodic cache save
	go s.startPeriodicSave()
	
	buf := make([]byte, 512)
	
	for {
		select {
		case <-ctx.Done():
			MainLog.Info("DNS server was terminated")
			CacheDB.Save()
			NegativeCache.Save()
			return ctx.Err()
		default:
			s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				MainLog.Errorf("Error reading UDP: %v", err)
				continue
			}
			
			data := make([]byte, n)
			copy(data, buf[:n])
			
			go s.handleRequest(data, addr)
		}
	}
}

func (s *DNSServer) handleRequest(data []byte, addr *net.UDPAddr) {
	client, err := NewDoHProxyClient(data, addr, s.conn, s.activeTasks)
	if err != nil {
		MainLog.Errorf("Failed to create DoH client: %v", err)
		return
	}
	
	domain := client.qdomain
	
	// Prevent duplicate queries
	if _, loaded := s.activeTasks.LoadOrStore(domain, true); loaded {
		MainLog.Debugf("Duplicate DNS query ignored: %s", domain)
		return
	}
	defer s.activeTasks.Delete(domain)
	
	ctx, cancel := context.WithTimeout(context.Background(), RequestTimeout)
	defer cancel()
	
	if err := client.Query(ctx); err != nil {
		MainLog.Errorf("DoH proxy error: %v", err)
	}
}

func (s *DNSServer) startPeriodicSave() {
	CacheDB.StartPeriodicSave()
	NegativeCache.StartPeriodicSave()
}

// Close closes the DNS server
func (s *DNSServer) Close() error {
	MainLog.Info("DNS Server stopped")
	return s.conn.Close()
}