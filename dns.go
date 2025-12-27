package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNS constants
const (
	QTypeA     = 1
	QTypeAAAA  = 28
	QTypeCNAME = 5
	QTypeSOA   = 6
	QTypeOPT   = 41
	QClass     = 1
	MinimumTTL = 300
)

var (
	QDomainPtr = []byte{0xc0, 0x0c}
)

// RCodeMapping maps response codes to descriptions
var RCodeMapping = map[int]string{
	0:  "NOERROR (Query successful)",
	1:  "FORMERR (Format error)",
	2:  "SERVFAIL (Server failure)",
	3:  "NXDOMAIN (Non-existent domain)",
	4:  "NOTIMP (Not implemented)",
	5:  "REFUSED (Server refused the request)",
	6:  "YXDOMAIN (Domain name exists)",
	7:  "YXRRSET (Resource record set exists)",
	8:  "NXRRSET (Resource record set does not exist)",
	9:  "NOTAUTH (Not an authoritative server)",
	10: "NOTZONE (Operation out of zone scope)",
}

// QTypeMapping maps query types to field names
var QTypeMapping = map[int]string{
	QTypeA:     "ip",
	QTypeAAAA:  "ipv6",
	QTypeCNAME: "cname",
}

// DNSMessage represents a DNS message
type DNSMessage struct {
	packet       []byte
	qEndOffset   int
	responseTTL  int
	fromResponse bool
	tid          uint16
	qdcount      uint16
	ancount      uint16
	nscount      uint16
	arcount      uint16
	qdomain      string
	qtype        uint16
	rrRecords    []RRRecord
	cacheValue   string
	nxDomain     bool
}

// RRRecord represents a resource record
type RRRecord struct {
	Name   string
	Type   uint16
	Class  uint16
	TTL    uint32
	RData  string
}

// NewDNSMessage creates a new DNS message
func NewDNSMessage(data []byte, fromResponse bool) (*DNSMessage, error) {
	msg := &DNSMessage{
		packet:       data,
		fromResponse: fromResponse,
		rrRecords:    make([]RRRecord, 0),
	}

	if len(data) == 0 {
		return msg, nil
	}

	if err := msg.unpack(); err != nil {
		return nil, err
	}

	return msg, nil
}

func (m *DNSMessage) unpack() error {
	if len(m.packet) < 16 {
		return fmt.Errorf("DNS packet too short: %d bytes", len(m.packet))
	}

	if err := m.unpackHeader(); err != nil {
		return fmt.Errorf("header error: %w", err)
	}

	if err := m.unpackQuestion(); err != nil {
		return fmt.Errorf("question error: %w", err)
	}

	if m.fromResponse {
		offset, err := m.unpackAnswer()
		if err != nil {
			// 记录错误但不中断，某些服务器可能返回不完整的响应
			MainLog.Warnf("Answer parsing error: %v", err)
			return nil // 继续处理，不返回错误
		}

		offset, err = m.unpackAuthority(offset)
		if err != nil {
			MainLog.Warnf("Authority parsing error: %v", err)
			return nil
		}

		_, err = m.unpackAdditional(offset)
		if err != nil {
			MainLog.Warnf("Additional parsing error: %v", err)
			return nil
		}
	}

	return nil
}

func (m *DNSMessage) unpackHeader() error {
	m.tid = binary.BigEndian.Uint16(m.packet[0:2])
	flags := binary.BigEndian.Uint16(m.packet[2:4])
	m.qdcount = binary.BigEndian.Uint16(m.packet[4:6])
	m.ancount = binary.BigEndian.Uint16(m.packet[6:8])
	m.nscount = binary.BigEndian.Uint16(m.packet[8:10])
	m.arcount = binary.BigEndian.Uint16(m.packet[10:12])

	rcode := flags & 0x000F

	if m.fromResponse && rcode == 3 && m.ancount == 0 {
		m.nxDomain = true
		return nil
	}

	if rcode > 0 {
		meaning := RCodeMapping[int(rcode)]
		if meaning == "" {
			meaning = fmt.Sprintf("Unknown rcode: %d", rcode)
		}
		return fmt.Errorf("DNS error, rcode: %d, %s", rcode, meaning)
	}

	return nil
}

func (m *DNSMessage) unpackQuestion() error {
	domain, offset, err := m.unpackName(12, true)
	if err != nil {
		return err
	}
	m.qdomain = domain

	if offset+4 > len(m.packet) {
		return fmt.Errorf("question section too short")
	}

	m.qtype = binary.BigEndian.Uint16(m.packet[offset : offset+2])
	m.qEndOffset = offset + 4

	return nil
}

func (m *DNSMessage) unpackAnswer() (int, error) {
	records, offset, err := m.unpackRRSection(int(m.ancount), m.qEndOffset)
	if err != nil {
		return offset, err
	}
	m.saveRRRecords(records)
	return offset, nil
}

func (m *DNSMessage) unpackAuthority(startOffset int) (int, error) {
	_, offset, err := m.unpackRRSection(int(m.nscount), startOffset)
	return offset, err
}

func (m *DNSMessage) unpackAdditional(startOffset int) (int, error) {
	records, offset, err := m.unpackRRSection(int(m.arcount), startOffset)
	if err != nil {
		return offset, err
	}
	m.saveRRRecords(records)
	return offset, nil
}

func (m *DNSMessage) unpackRRSection(count, startOffset int) ([]RRRecord, int, error) {
	records := make([]RRRecord, 0)
	offset := startOffset

	for i := 0; i < count; i++ {
		// 严格的边界检查
		if offset < 0 || offset >= len(m.packet) {
			MainLog.Warnf("Invalid offset %d in RR section", offset)
			return records, offset, fmt.Errorf("invalid offset in RR section")
		}

		name, newOffset, err := m.unpackName(offset, false)
		if err != nil {
			MainLog.Warnf("Failed to unpack name at offset %d: %v", offset, err)
			return records, offset, err
		}
		offset = newOffset

		if offset+10 > len(m.packet) {
			MainLog.Warnf("RR section too short at offset %d", offset)
			return records, offset, fmt.Errorf("RR section too short")
		}

		rrType := binary.BigEndian.Uint16(m.packet[offset : offset+2])
		class := binary.BigEndian.Uint16(m.packet[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(m.packet[offset+4 : offset+8])
		rdLength := binary.BigEndian.Uint16(m.packet[offset+8 : offset+10])
		offset += 10

		if offset+int(rdLength) > len(m.packet) {
			MainLog.Warnf("RDATA too short at offset %d, rdLength %d", offset, rdLength)
			return records, offset, fmt.Errorf("RDATA too short")
		}

		// 保存 rdata 起始位置和数据
		rdataStart := offset
		rdataBytes := m.packet[rdataStart : rdataStart+int(rdLength)]

		// 解析 RDATA
		rdata := m.parseRDataSafe(rrType, rdataBytes, rdataStart)
		offset += int(rdLength)

		// 只记录成功解析的记录
		if rdata != "" {
			records = append(records, RRRecord{
				Name:  name,
				Type:  rrType,
				Class: class,
				TTL:   ttl,
				RData: rdata,
			})
		}
	}

	return records, offset, nil
}

// parseRDataSafe 安全地解析RDATA，带异常捕获
func (m *DNSMessage) parseRDataSafe(rrType uint16, rdataBytes []byte, rdataOffset int) (result string) {
	// 使用defer recover防止panic
	defer func() {
		if r := recover(); r != nil {
			MainLog.Warnf("Panic in parseRData: %v, type=%d, offset=%d", r, rrType, rdataOffset)
			result = ""
		}
	}()

	return m.parseRData(rrType, rdataBytes, rdataOffset)
}

func (m *DNSMessage) parseRData(rrType uint16, rdataBytes []byte, rdataOffset int) string {
	switch rrType {
	case QTypeA:
		if len(rdataBytes) == 4 {
			return net.IP(rdataBytes).String()
		}
	case QTypeAAAA:
		if len(rdataBytes) == 16 {
			return net.IP(rdataBytes).String()
		}
	case QTypeCNAME:
		// 对于CNAME，首先尝试直接解析rdataBytes（无压缩的情况）
		name := m.parseUncompressedName(rdataBytes)
		if name != "" {
			return name
		}

		// 如果直接解析失败，尝试使用offset（可能有压缩指针）
		if rdataOffset >= 0 && rdataOffset < len(m.packet) {
			name, _, err := m.unpackNameSafe(rdataOffset, false)
			if err == nil && name != "" {
				return name
			}
		}

		// 都失败了，返回十六进制
		return fmt.Sprintf("unparsed-cname:%x", rdataBytes)

	case QTypeSOA:
		return fmt.Sprintf("%d", MinimumTTL)
	case QTypeOPT:
		return fmt.Sprintf("OPT: %x", rdataBytes)
	}
	return fmt.Sprintf("%x", rdataBytes)
}

// parseUncompressedName 解析未压缩的域名（从rdata字节直接解析）
func (m *DNSMessage) parseUncompressedName(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	parts := make([]string, 0)
	offset := 0

	for offset < len(data) {
		length := int(data[offset])
		offset++

		if length == 0 {
			break
		}

		// 遇到压缩指针，停止解析
		if length >= 192 {
			return ""
		}

		if offset+length > len(data) {
			return ""
		}

		label := string(data[offset : offset+length])
		parts = append(parts, label)
		offset += length
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ".")
}

// unpackNameSafe 带panic恢复的unpackName
func (m *DNSMessage) unpackNameSafe(startOffset int, qSection bool) (name string, offset int, err error) {
	defer func() {
		if r := recover(); r != nil {
			MainLog.Warnf("Panic in unpackName: %v, offset=%d", r, startOffset)
			name = ""
			offset = startOffset
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	return m.unpackName(startOffset, qSection)
}

func (m *DNSMessage) unpackName(startOffset int, qSection bool) (string, int, error) {
	// 严格的边界检查
	if startOffset < 0 {
		return "", startOffset, fmt.Errorf("negative offset: %d", startOffset)
	}

	if startOffset >= len(m.packet) {
		return "", startOffset, fmt.Errorf("offset %d beyond packet length %d", startOffset, len(m.packet))
	}

	offset := startOffset
	parts := make([]string, 0)
	visited := make(map[int]bool)
	maxJumps := 10
	jumps := 0

	for offset < len(m.packet) {
		// 确保可以读取length字节
		if offset >= len(m.packet) {
			return "", offset, fmt.Errorf("unexpected end at offset %d", offset)
		}

		length := int(m.packet[offset])
		offset++

		if length == 0 {
			break
		}

		if qSection && length > 63 {
			return "", offset, fmt.Errorf("label length %d > 63", length)
		}

		// Compression pointer
		if !qSection && length >= 192 {
			if offset >= len(m.packet) {
				return "", offset, fmt.Errorf("compression pointer incomplete")
			}

			pointer := ((length & 0x3F) << 8) | int(m.packet[offset])
			offset++

			// 严格检查指针范围
			if pointer < 0 || pointer >= len(m.packet) {
				return "", offset, fmt.Errorf("invalid pointer: %d", pointer)
			}

			// 检查指针不能指向后面
			if pointer >= startOffset {
				return "", offset, fmt.Errorf("forward pointer: %d", pointer)
			}

			if visited[pointer] {
				return "", offset, fmt.Errorf("pointer loop at %d", pointer)
			}
			visited[pointer] = true

			jumps++
			if jumps > maxJumps {
				return "", offset, fmt.Errorf("too many jumps")
			}

			jumpedName, _, err := m.unpackName(pointer, false)
			if err != nil {
				MainLog.Warnf("Failed to follow pointer %d: %v", pointer, err)
				// 返回已解析的部分
				if len(parts) > 0 {
					return strings.Join(parts, "."), offset, nil
				}
				return "", offset, err
			}

			if jumpedName != "" {
				parts = append(parts, jumpedName)
			}
			break
		}

		// 普通标签
		if offset+length > len(m.packet) {
			return "", offset, fmt.Errorf("label extends beyond packet")
		}

		label := string(m.packet[offset : offset+length])
		parts = append(parts, label)
		offset += length
	}

	name := strings.Join(parts, ".")
	return name, offset, nil
}

func (m *DNSMessage) saveRRRecords(records []RRRecord) {
	for _, record := range records {
		if record.Type == QTypeA || record.Type == QTypeAAAA || record.Type == QTypeCNAME {
			m.rrRecords = append(m.rrRecords, record)
		}
	}
}

// BuildResponse builds a DNS response from cache
func (m *DNSMessage) BuildResponse(value string, ttlExpireTime int64) []byte {
	m.cacheValue = value

	header := m.buildHeader()
	question := m.packet[12:m.qEndOffset]
	answer := m.buildResponseAnswer(ttlExpireTime)

	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(question)
	buf.Write(answer)

	return buf.Bytes()
}

// BuildErrorResponse builds an NXDOMAIN response
func (m *DNSMessage) BuildErrorResponse() []byte {
	header := m.buildErrorHeader()
	question := m.packet[12:m.qEndOffset]

	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(question)

	return buf.Bytes()
}

func (m *DNSMessage) buildHeader() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], m.tid)
	binary.BigEndian.PutUint16(buf[2:4], 0x8180) // Standard response
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(buf[6:8], 1)      // ANCOUNT
	return buf
}

func (m *DNSMessage) buildErrorHeader() []byte {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint16(buf[0:2], m.tid)
	binary.BigEndian.PutUint16(buf[2:4], 0x8183) // NXDOMAIN
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(buf[6:8], 0)      // ANCOUNT
	return buf
}

func (m *DNSMessage) buildResponseAnswer(ttlExpireTime int64) []byte {
	var buf bytes.Buffer

	buf.Write(QDomainPtr)

	typeBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBuf, m.qtype)
	buf.Write(typeBuf)

	classBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(classBuf, QClass)
	buf.Write(classBuf)

	ttl := m.buildAnswerTTL(ttlExpireTime)
	ttlBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(ttlBuf, uint32(ttl))
	buf.Write(ttlBuf)

	rdata := m.buildAnswerRData()
	rdLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(rdLenBuf, uint16(len(rdata)))
	buf.Write(rdLenBuf)
	buf.Write(rdata)

	return buf.Bytes()
}

func (m *DNSMessage) buildAnswerTTL(ttlExpireTime int64) int64 {
	ttl := ttlExpireTime - time.Now().Unix()
	if ttl < 0 {
		ttl = MinimumTTL
	}
	return ttl
}

func (m *DNSMessage) buildAnswerRData() []byte {
	switch m.qtype {
	case QTypeA:
		ip := net.ParseIP(m.cacheValue)
		if ip != nil {
			return ip.To4()
		}
	case QTypeAAAA:
		ip := net.ParseIP(m.cacheValue)
		if ip != nil {
			return ip.To16()
		}
	case QTypeCNAME:
		return m.buildDomainName(m.cacheValue)
	}
	return []byte{}
}

// BuildQuery builds a DNS query message
func BuildQuery(domain string) []byte {
	var buf bytes.Buffer

	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0x1234) // Transaction ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100) // Standard query
	binary.BigEndian.PutUint16(header[4:6], 1)      // QDCOUNT
	buf.Write(header)

	buf.Write(buildDomainName(domain))
	buf.WriteByte(0)

	typeBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBuf, QTypeA)
	buf.Write(typeBuf)

	classBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(classBuf, QClass)
	buf.Write(classBuf)

	return buf.Bytes()
}

func (m *DNSMessage) buildDomainName(domain string) []byte {
	return buildDomainName(domain)
}

func buildDomainName(domain string) []byte {
	var buf bytes.Buffer
	labels := strings.Split(domain, ".")

	for _, label := range labels {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}

	return buf.Bytes()
}

// Getters
func (m *DNSMessage) GetDomain() string {
	return m.qdomain
}

func (m *DNSMessage) GetQType() uint16 {
	return m.qtype
}

func (m *DNSMessage) GetRRRecords() []RRRecord {
	return m.rrRecords
}

func (m *DNSMessage) IsNXDomain() bool {
	return m.nxDomain
}