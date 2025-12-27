# DNS DoH Proxy (Golang Edition)

A high-performance DNS over HTTPS (DoH) proxy server implemented in Go, featuring intelligent DNS splitting, cache management, and fastest-IP selection. 

## Features

✅ **Full Feature Port** - Functionally identical to the Python version:[DoH Proxy Python Edition](https://github.com/crb912/SmartDoHProxy)
* **DNS over HTTPS (DoH) Support**
* **Smart DNS Splitting** (Based on GFWList rules)
* **Persistent DNS Cache**
* **Negative Caching** (NXDOMAIN)
* **Fastest IP Selection** (via TCP Ping)
* **HTTP/HTTPS Proxy Support**
* **Bootstrap Mechanism** (For resolving DoH server hostnames)
* **Concurrency** (Powered by Goroutines)

## Project Structure

├── main.go # Entry point 
├── config.go # Configuration loading and management 
├── dns.go # DNS message parsing and construction 
├── doh.go # DoH client and server logic 
├── config.toml # Configuration file 
├── go.mod # Go module dependencies 
└── README.md # Documentation

## Build

```bash
go mod tidy
# Linux/Mac
go build -o dohproxygo

# Windows
go build -o dohproxygo.exe
```
## Configuration

Edit the `config.toml` file

## Usage
Linux:
```
# Run directly:
sudo ./dohproxygo
# Run in background:
sudo nohup ./dohproxygo > dns.log 2>&1 &
```
Using systemd (Recommended): Create `/etc/systemd/system/dohproxygo.service` and use `systemctl` to manage.

Windows:
```
nssm install DoHDNSProxy "C:\path\to\dohproxygo.exe"
nssm start DoHDNSProxy
```
## Troubleshooting
- **Port Occupied**: Use `lsof -i :53` (Linux/Mac) or `netstat -ano | findstr :53` (Windows) to check.
- **Permissions**: Listening on port 53 usually requires root/administrator privileges.
- **Test**: Use dig @127.0.0.1 google.com to verify resolution.

## Test and Benchmark with dnsperf

- Cache hit：  `8100 QPS` (Queries per second).
- To simulate DNS cache misses, I tested with 1000 different domains. The measured performance was `1571 QPS`. Test data is from Majestic Million (top 1 million root domains)[Download CSV ](https://downloads.majestic.com/majestic_million.csv)

## Differences from Python Version

- Performance: Significantly improved performance.
- Concurrency: Native Goroutines without GIL limitations.
- Resources: Lower memory footprint and faster startup.
- Deployment: Single binary without needing a Python environment.

---

# DNS DoH Proxy (Golang版本)

这是一个高性能的DNS over HTTPS (DoH)代理服务器，使用Go语言实现，支持智能DNS分流、缓存管理和最快IP选择。

## 功能特性

✅ **完整功能移植** - 与Python版本功能完全一致
- DNS over HTTPS (DoH) 支持
- 智能DNS分流（基于GFWList规则）
- 持久化DNS缓存
- 负向缓存（NXDOMAIN）
- 最快IP自动选择（TCP Ping）
- HTTP/HTTPS代理支持
- Bootstrap机制（解析DoH服务器域名）
- 并发处理（使用Goroutine）

## 项目结构

```
.
├── main.go         # 程序入口
├── config.go       # 配置加载和管理
├── dns.go          # DNS消息解析和构建
├── doh.go          # DoH客户端和服务器
├── config.toml     # 配置文件
├── go.mod          # Go模块依赖
└── README.md       # 本文件
```

## 安装与编译

### 前置要求
- Go 1.21 或更高版本

### 编译步骤

1. 克隆或下载代码到本地

2. 下载依赖包：
```bash
go mod tidy
```

3. 编译程序：
```bash
# Linux/Mac
go build -o doh-dns-proxy

# Windows
go build -o doh-dns-proxy.exe
```

4. 交叉编译（可选）：
```bash
# 编译Linux版本
GOOS=linux GOARCH=amd64 go build -o doh-dns-proxy-linux

# 编译Windows版本
GOOS=windows GOARCH=amd64 go build -o doh-dns-proxy.exe

# 编译Mac版本
GOOS=darwin GOARCH=amd64 go build -o doh-dns-proxy-mac
```

## 配置说明

编辑 `config.toml` 文件：

```toml
[doh_servers]
# 直连DoH服务器（国内）
direct_servers = [
    "https://doh.pub/dns-query",       # 腾讯
    "https://dns.alidns.com/dns-query" # 阿里
]

# 代理DoH服务器（国外）
proxy_servers = [
    "https://dns.google/dns-query",   # Google
    "https://1.1.1.1/dns-query",      # Cloudflare
]

# Bootstrap服务器（用于解析DoH服务器域名）
bootstrap_server = "223.5.5.5"

[dns]
host = '0.0.0.0'  # 监听地址，0.0.0.0表示所有网卡
port = 53         # DNS服务端口

[cache]
max_size = 5000000        # 最大缓存条目数
path = 'dns_cache.json'   # 缓存文件路径
save_interval = 72        # 自动保存间隔（小时）

[proxy]
enable_proxy = false                  # 启用代理功能
http = "http://192.168.5.8:7899"      # HTTP代理地址
https = "http://192.168.5.8:7899"     # HTTPS代理地址
rule_file = "gfwlist.txt"             # 本地规则文件
rule_file_url = "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"

[logging]
# 日志级别: DEBUG, INFO, WARNING, ERROR
default_log_level = "INFO"
query_log_level = "INFO"
```

## 使用方法

### Linux/Mac

1. 直接运行：
```bash
sudo ./doh-dns-proxy
```

2. 后台运行：
```bash
sudo nohup ./doh-dns-proxy > dns.log 2>&1 &
```

3. 使用systemd服务（推荐）：

创建 `/etc/systemd/system/doh-dns-proxy.service`：
```ini
[Unit]
Description=DoH DNS Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/doh-dns-proxy
ExecStart=/opt/doh-dns-proxy/doh-dns-proxy
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

启动服务：
```bash
sudo systemctl daemon-reload
sudo systemctl enable doh-dns-proxy
sudo systemctl start doh-dns-proxy
sudo systemctl status doh-dns-proxy
```

### Windows

1. 管理员权限运行 `doh-dns-proxy.exe`

2. 使用NSSM创建Windows服务（推荐）：
```cmd
nssm install DoHDNSProxy "C:\path\to\doh-dns-proxy.exe"
nssm start DoHDNSProxy
```

## 配置系统DNS

### Linux

编辑 `/etc/resolv.conf`：
```
nameserver 127.0.0.1
```

或使用NetworkManager：
```bash
nmcli connection modify <connection-name> ipv4.dns "127.0.0.1"
nmcli connection up <connection-name>
```

### Windows

1. 打开"网络和共享中心"
2. 点击网络连接 → 属性
3. 选择"Internet 协议版本 4 (TCP/IPv4)" → 属性
4. 设置首选DNS为 `127.0.0.1`

### macOS

```bash
networksetup -setdnsservers Wi-Fi 127.0.0.1
```

## 性能优化建议

1. **调整缓存大小**：根据系统内存调整 `max_size` 参数
2. **日志级别**：生产环境建议使用 WARNING 级别
3. **代理配置**：仅在需要时启用代理功能
4. **Bootstrap服务器**：选择延迟最低的DNS服务器

## 监控与日志

程序会输出到标准输出，可以查看实时日志：

```bash
# 查看实时日志
tail -f dns.log

# 查看查询日志（如果配置为文件输出）
tail -f query.log
```

## 故障排查

### 端口占用
```bash
# Linux/Mac
sudo lsof -i :53
sudo netstat -tuln | grep :53

# Windows
netstat -ano | findstr :53
```

### 权限问题
在Linux/Mac上，监听1024以下端口需要root权限：
```bash
sudo ./doh-dns-proxy
```

### 测试DNS解析
```bash
# 使用dig测试
dig @127.0.0.1 google.com

# 使用nslookup测试
nslookup google.com 127.0.0.1
```

## 与Python版本的差异

1. **性能提升**：Go版本性能显著优于Python版本
2. **并发处理**：使用原生Goroutine，无GIL限制
3. **内存占用**：更低的内存占用和更快的启动速度
4. **部署方便**：编译为单一可执行文件，无需Python环境

## Go语言特性

- ✅ 使用标准库 `net` 实现UDP服务器
- ✅ 使用 `sync.Map` 实现并发安全的活动任务追踪
- ✅ 使用 `context` 实现优雅关闭
- ✅ 使用 `goroutine` 实现并发查询和后台任务
- ✅ 使用 `sync.RWMutex` 实现读写锁
- ✅ 遵循Go官方代码规范

## 开发与调试

```bash
# 运行程序
go run .

# 开启竞态检测
go run -race .

# 性能分析
go build -o doh-dns-proxy
./doh-dns-proxy -cpuprofile=cpu.prof -memprofile=mem.prof

# 查看profile
go tool pprof cpu.prof
```

## License

本项目基于原Python版本移植，保持功能一致性。

## 贡献

欢迎提交Issue和Pull Request！

## 注意事项

⚠️ **安全提示**：
- 请勿在公网直接暴露DNS服务
- 建议使用防火墙限制访问来源
- 定期更新GFWList规则文件
- 生产环境建议使用systemd或NSSM管理服务

## 技术支持

如有问题，请提交Issue或查看日志文件进行故障排查。
