package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config structures
type Config struct {
	DOHServers DOHServers `toml:"doh_servers"`
	DNS        DNSConfig  `toml:"dns"`
	Cache      CacheConfig `toml:"cache"`
	Proxy      ProxyConfig `toml:"proxy"`
	Logging    LogConfig  `toml:"logging"`
}

type DOHServers struct {
	DirectServers    []string `toml:"direct_servers"`
	ProxyServers     []string `toml:"proxy_servers"`
	BootstrapServer  string   `toml:"bootstrap_server"`
}

type DNSConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
}

type CacheConfig struct {
	MaxSize      int    `toml:"max_size"`
	Path         string `toml:"path"`
	SaveInterval int    `toml:"save_interval"` // hours
}

type ProxyConfig struct {
	EnableProxy bool   `toml:"enable_proxy"`
	HTTP        string `toml:"http"`
	HTTPS       string `toml:"https"`
	RuleFile    string `toml:"rule_file"`
	RuleFileURL string `toml:"rule_file_url"`
}

type LogConfig struct {
	DefaultLogLevel string `toml:"default_log_level"`
	QueryLogLevel   string `toml:"query_log_level"`
}

// Global config
var (
	Cfg          *Config
	MainLog      *logrus.Logger
	QueryLog     *logrus.Logger
	CacheDB      *LimitedPersistentDict
	NegativeCache *LimitedPersistentDict
	TrafficClassifier *TrafficClass
)

// LoadConfig loads configuration from TOML file
func LoadConfig(configPath string) (*Config, error) {
	cfg := &Config{}
	if _, err := toml.DecodeFile(configPath, cfg); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	return cfg, nil
}

// GetProxies returns proxy configuration
func (c *Config) GetProxies() map[string]string {
	if !c.Proxy.EnableProxy {
		return nil
	}
	return map[string]string{
		"http":  c.Proxy.HTTP,
		"https": c.Proxy.HTTPS,
	}
}

// GetDOHHostnames extracts hostnames from DOH server URLs
func (c *Config) GetDOHHostnames() map[string]bool {
	hostnames := make(map[string]bool)
	allServers := append(c.DOHServers.DirectServers, c.DOHServers.ProxyServers...)
	
	for _, serverURL := range allServers {
		if u, err := url.Parse(serverURL); err == nil && u.Hostname() != "" {
			hostnames[u.Hostname()] = true
		}
	}
	return hostnames
}

// InitLogger initializes loggers with log rotation
func InitLogger(cfg *Config) {
	// 创建日志目录
	os.MkdirAll("logs", 0755)
	
	// Main log with rotation
	mainLogWriter := &lumberjack.Logger{
		Filename:   "logs/main.log",
		MaxSize:    10,    // MB
		MaxBackups: 5,     // 保留5个备份
		MaxAge:     30,    // 天
		Compress:   true,  // 压缩旧日志
	}
	
	MainLog = logrus.New()
	MainLog.SetOutput(mainLogWriter)
	mainLevel, _ := logrus.ParseLevel(strings.ToLower(cfg.Logging.DefaultLogLevel))
	MainLog.SetLevel(mainLevel)
	MainLog.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	})
	
	// Query log with rotation
	queryLogWriter := &lumberjack.Logger{
		Filename:   "logs/query.log",
		MaxSize:    50,    // MB（查询日志通常更大）
		MaxBackups: 3,
		MaxAge:     7,
		Compress:   true,
	}
	
	QueryLog = logrus.New()
	QueryLog.SetOutput(queryLogWriter)
	queryLevel, _ := logrus.ParseLevel(strings.ToLower(cfg.Logging.QueryLogLevel))
	QueryLog.SetLevel(queryLevel)
	QueryLog.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
	})
	
	// 启动信息输出到控制台
	fmt.Printf("✓ Logs configured with rotation:\n")
	fmt.Printf("  Main log:  logs/main.log (max 10MB, 5 backups)\n")
	fmt.Printf("  Query log: logs/query.log (max 50MB, 3 backups)\n")
	
	MainLog.Infof("=== DNS DoH Proxy Started ===")
}

// 如果需要同时输出到控制台和文件
func InitLoggerDual(cfg *Config) {
	os.MkdirAll("logs", 0755)
	
	// Main log
	mainLogWriter := &lumberjack.Logger{
		Filename:   "logs/main.log",
		MaxSize:    10,
		MaxBackups: 5,
		MaxAge:     30,
		Compress:   true,
	}
	
	MainLog = logrus.New()
	MainLog.SetOutput(io.MultiWriter(os.Stdout, mainLogWriter))
	mainLevel, _ := logrus.ParseLevel(strings.ToLower(cfg.Logging.DefaultLogLevel))
	MainLog.SetLevel(mainLevel)
	MainLog.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	
	// Query log
	queryLogWriter := &lumberjack.Logger{
		Filename:   "logs/query.log",
		MaxSize:    50,
		MaxBackups: 3,
		MaxAge:     7,
		Compress:   true,
	}
	
	QueryLog = logrus.New()
	QueryLog.SetOutput(io.MultiWriter(os.Stdout, queryLogWriter))
	queryLevel, _ := logrus.ParseLevel(strings.ToLower(cfg.Logging.QueryLogLevel))
	QueryLog.SetLevel(queryLevel)
	QueryLog.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
	
	MainLog.Infof("=== DNS DoH Proxy Started ===")
}

// LimitedPersistentDict - Thread-safe persistent dictionary with size limit
type LimitedPersistentDict struct {
	mu               sync.RWMutex
	data             map[string]map[string]interface{}
	filepath         string
	maxSize          int
	autoSaveInterval time.Duration
	insertOrder      []string
}

// NewLimitedPersistentDict creates a new persistent dictionary
func NewLimitedPersistentDict(filepath string, maxSize int, saveInterval int) *LimitedPersistentDict {
	dict := &LimitedPersistentDict{
		data:             make(map[string]map[string]interface{}),
		filepath:         filepath,
		maxSize:          maxSize,
		autoSaveInterval: time.Duration(saveInterval) * time.Second,
		insertOrder:      make([]string, 0),
	}
	dict.load()
	return dict
}

func (d *LimitedPersistentDict) Set(key string, value map[string]interface{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	
	if len(d.data) >= d.maxSize {
		d.cleanup()
	}
	
	if _, exists := d.data[key]; !exists {
		d.insertOrder = append(d.insertOrder, key)
	}
	d.data[key] = value
}

func (d *LimitedPersistentDict) Get(key string) (map[string]interface{}, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	val, exists := d.data[key]
	return val, exists
}

func (d *LimitedPersistentDict) Contains(key string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, exists := d.data[key]
	return exists
}

func (d *LimitedPersistentDict) cleanup() {
	removeCount := len(d.data) / 2
	MainLog.Infof("Cache full (%d/%d), cleaning up %d entries", len(d.data), d.maxSize, removeCount)
	
	for i := 0; i < removeCount && i < len(d.insertOrder); i++ {
		key := d.insertOrder[i]
		delete(d.data, key)
	}
	d.insertOrder = d.insertOrder[removeCount:]
}

func (d *LimitedPersistentDict) load() {
	file, err := os.Open(d.filepath)
	if err != nil {
		MainLog.Infof("DB file %s not found", d.filepath)
		return
	}
	defer file.Close()
	
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&d.data); err != nil {
		MainLog.Errorf("Failed to load cache: %v", err)
		return
	}
	
	// Rebuild insert order
	for key := range d.data {
		d.insertOrder = append(d.insertOrder, key)
	}
	
	MainLog.Infof("DB loaded from %s, entries: %d", d.filepath, len(d.data))
	
	if len(d.data) > d.maxSize {
		d.cleanup()
	}
}

func (d *LimitedPersistentDict) Save() {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	file, err := os.Create(d.filepath)
	if err != nil {
		MainLog.Errorf("Failed to create cache file: %v", err)
		return
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(d.data); err != nil {
		MainLog.Errorf("Failed to save cache: %v", err)
		return
	}
	
	MainLog.Infof("DB saved to %s, entries: %d", d.filepath, len(d.data))
}

func (d *LimitedPersistentDict) StartPeriodicSave() {
	MainLog.Infof("DB persistence task started: %s, interval: %d hours", 
		d.filepath, int(d.autoSaveInterval.Hours()))
	
	ticker := time.NewTicker(d.autoSaveInterval)
	go func() {
		for range ticker.C {
			d.Save()
		}
	}()
}

// TrafficClass - Traffic classifier based on GFWList
type TrafficClass struct {
	proxyDomains map[string]bool
	mu           sync.RWMutex
}

func NewTrafficClassifier(filepath, fileURL string) *TrafficClass {
	tc := &TrafficClass{
		proxyDomains: make(map[string]bool),
	}
	
	if !Cfg.Proxy.EnableProxy {
		return tc
	}
	
	tc.loadAndParse(filepath, fileURL)
	return tc
}

func (tc *TrafficClass) loadAndParse(filepath, fileURL string) {
	content := tc.readFile(filepath)
	if content == "" {
		content = tc.downloadFile(fileURL)
	}
	
	if content != "" {
		tc.parseRules(content)
		MainLog.Infof("Rule set loaded successfully, entries: %d", len(tc.proxyDomains))
		tc.saveFile(filepath, content)
	}
}

func (tc *TrafficClass) readFile(filepath string) string {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return ""
	}
	
	MainLog.Infof("Rule set loaded from %s", filepath)
	
	// Try base64 decode
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err == nil {
		return string(decoded)
	}
	return string(data)
}

func (tc *TrafficClass) saveFile(filepath, content string) {
	if err := os.WriteFile(filepath, []byte(content), 0644); err != nil {
		MainLog.Errorf("Failed to save rule file: %v", err)
	}
}

func (tc *TrafficClass) downloadFile(fileURL string) string {
	resp, err := http.Get(fileURL)
	if err != nil {
		MainLog.Errorf("Failed to download rule file: %v", err)
		return ""
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		MainLog.Errorf("Failed to read rule file: %v", err)
		return ""
	}
	
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		MainLog.Errorf("Failed to decode rule file: %v", err)
		return ""
	}
	
	MainLog.Infof("Rule set downloaded from %s", fileURL)
	return string(decoded)
}

func (tc *TrafficClass) parseRules(content string) {
	domainPattern := regexp.MustCompile(`(?:\|\||\|)?([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*)`)
	
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.Contains(line, "Whitelist") {
			break
		}
		
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		
		matches := domainPattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 1 {
				domain := strings.ToLower(match[1])
				domain = strings.TrimPrefix(domain, "http://")
				domain = strings.TrimPrefix(domain, "https://")
				tc.proxyDomains[domain] = true
			}
		}
	}
}

func (tc *TrafficClass) Contains(domain string) bool {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	
	// Check exact match
	if tc.proxyDomains[domain] {
		return true
	}
	
	// Check subdomain match
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parentDomain := strings.Join(parts[i:], ".")
		if tc.proxyDomains[parentDomain] {
			return true
		}
	}
	
	return false
}

// Initialize global objects
func InitGlobals() {
	var err error
	Cfg, err = LoadConfig("config.toml")
	if err != nil {
		panic(err)
	}
	
	InitLogger(Cfg)
	
	saveInterval := Cfg.Cache.SaveInterval * 3600
	CacheDB = NewLimitedPersistentDict(Cfg.Cache.Path, Cfg.Cache.MaxSize, saveInterval)
	NegativeCache = NewLimitedPersistentDict("negative_cache.json", 1000, saveInterval)
	
	TrafficClassifier = NewTrafficClassifier(Cfg.Proxy.RuleFile, Cfg.Proxy.RuleFileURL)
}