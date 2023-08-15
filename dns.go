package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"math/rand"
	"strings"
)

type (
	DNS[P any] interface {
		FromBytes(reader *bytes.Reader) error
		*P
	}

	DNSHeader struct {
		Id                                                       uint16
		Flags                                                    uint16
		NumQuestions, NumAnswers, NumAuthorities, NumAdditionals uint16
	}

	DNSQuestion struct {
		Name  []byte
		Type  uint16
		Class uint16
	}

	DNSRecord struct {
		Name        []byte
		Data        []byte
		Type, Class uint16
		TTL         uint32
	}

	DNSPacket struct {
		Header      *DNSHeader
		Questions   *[]DNSQuestion
		Answers     *[]DNSRecord
		Authorities *[]DNSRecord
		Additionals *[]DNSRecord
	}
)

const (
	RecursionDesired = uint16(1 << 8)

	TypeA  = 1
	TypeNS = 2

	ClassIn = 1
)

func (dh *DNSHeader) Bytes() []byte {
	res := make([]byte, 12)
	binary.BigEndian.PutUint16(res, dh.Id)
	binary.BigEndian.PutUint16(res[2:], dh.Flags)
	binary.BigEndian.PutUint16(res[4:], dh.NumQuestions)
	binary.BigEndian.PutUint16(res[6:], dh.NumAnswers)
	binary.BigEndian.PutUint16(res[8:], dh.NumAuthorities)
	binary.BigEndian.PutUint16(res[10:], dh.NumAdditionals)
	return res
}

func (dh *DNSHeader) FromBytes(reader *bytes.Reader) error {
	data := make([]byte, 12)
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	dh.Id = binary.BigEndian.Uint16(data)
	dh.Flags = binary.BigEndian.Uint16(data[2:])
	dh.NumQuestions = binary.BigEndian.Uint16(data[4:])
	dh.NumAnswers = binary.BigEndian.Uint16(data[6:])
	dh.NumAuthorities = binary.BigEndian.Uint16(data[8:])
	dh.NumAdditionals = binary.BigEndian.Uint16(data[10:])
	return nil
}

func (dq *DNSQuestion) Bytes() []byte {
	res := make([]byte, 4)
	binary.BigEndian.PutUint16(res, dq.Type)
	binary.BigEndian.PutUint16(res[2:], dq.Class)
	return append(dq.Name, res...)
}

func (dq *DNSQuestion) FromBytes(reader *bytes.Reader) error {
	name, err := DecodeDomainName(reader)
	if err != nil {
		return err
	}
	dq.Name = []byte(name)
	data := make([]byte, 4)
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	dq.Type = binary.BigEndian.Uint16(data)
	dq.Class = binary.BigEndian.Uint16(data[2:])
	return nil
}

func (dp *DNSPacket) FromBytes(reader *bytes.Reader) error {
	var header DNSHeader
	if err := header.FromBytes(reader); err != nil {
		return err
	}
	dp.Header = &header
	questions, err := parseSlice[DNSQuestion](int(header.NumQuestions), reader)
	if err != nil {
		return err
	}
	dp.Questions = &questions
	answers, err := parseSlice[DNSRecord](int(header.NumAnswers), reader)
	if err != nil {
		return err
	}
	dp.Answers = &answers
	authorities, err := parseSlice[DNSRecord](int(header.NumAuthorities), reader)
	if err != nil {
		return err
	}
	dp.Authorities = &authorities
	additionals, err := parseSlice[DNSRecord](int(header.NumAdditionals), reader)
	if err != nil {
		return err
	}
	dp.Additionals = &additionals
	return nil
}

func parseSlice[T any, PT DNS[T]](size int, reader *bytes.Reader) ([]T, error) {
	slice := make([]T, size)
	for i := 0; i < size; i++ {
		p := PT(&slice[i])
		if err := p.FromBytes(reader); err != nil {
			return nil, err
		}
	}
	return slice, nil
}

// FromBytes creates a DNSRecord from the given sequence of bytes.
// Refer to Section 4.1.3 (Resource Record Format) of RFC 1035.
func (dr *DNSRecord) FromBytes(reader *bytes.Reader) error {
	// Set name attribute of variable length
	name, err := DecodeDomainName(reader)
	if err != nil {
		return err
	}
	dr.Name = []byte(name)
	// Set other attributes
	data := make([]byte, 10)
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	dr.Type = binary.BigEndian.Uint16(data)
	dr.Class = binary.BigEndian.Uint16(data[2:])
	dr.TTL = binary.BigEndian.Uint32(data[4:])
	readLen := binary.BigEndian.Uint16(data[8:])
	// Record type-specific parsing
	switch dr.Type {
	case TypeNS:
		domainName, err := DecodeDomainName(reader)
		if err != nil {
			return err
		}
		dr.Data = []byte(domainName)
	default:
		dr.Data = make([]byte, readLen)
		if _, err := io.ReadFull(reader, dr.Data); err != nil {
			return err
		}
	}
	return nil
}

// EncodeDomainName returns a slice of encoded bytes for the given domain name.
// e.g. google.com -> \x06google\x03com\x00
func EncodeDomainName(name string) ([]byte, error) {
	split := strings.Split(name, ".")
	var buf bytes.Buffer
	var err error
	for _, s := range split {
		err = buf.WriteByte(byte(len(s)))
		if err != nil {
			return nil, err
		}
		_, err = buf.Write([]byte(s))
		if err != nil {
			return nil, err
		}
	}
	// Null termination
	err = buf.WriteByte(byte(0))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecodeDomainName returns the original domain name from the encoded bytes
// e.g. \x06google\x03com\x00 -> google.com
func DecodeDomainName(reader *bytes.Reader) (string, error) {
	var res []string
	length, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	for length != 0 {
		if length&0b1100_0000 != 0 {
			part, err := DecodeDomainNameCompressed(length, reader)
			if err != nil {
				return "", err
			}
			res = append(res, part)
			break
		}
		bt := make([]byte, length)
		if _, err := io.ReadFull(reader, bt); err != nil {
			return "", err
		}
		res = append(res, string(bt))
		length, err = reader.ReadByte()
		if err != nil {
			return "", err
		}
	}
	return strings.Join(res, "."), nil
}

// DecodeDomainNameCompressed returns the original domain name from a
// message that follows the domain name compression scheme as in RFC 1035.
//
// The compression scheme takes the form of a two octet sequence:
//
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//	| 1  1|                OFFSET                   |
//	+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
func DecodeDomainNameCompressed(length byte, reader *bytes.Reader) (string, error) {
	// Parse offset info
	bt := make([]byte, 2)
	bt[0] = length & 0b0011_1111
	next, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	bt[1] = next
	offset := binary.BigEndian.Uint16(bt)
	// Move to offset and parse domain name
	currPos, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return "", err
	}
	if _, err := reader.Seek(int64(offset), io.SeekStart); err != nil {
		return "", err
	}
	res, err := DecodeDomainName(reader)
	if err != nil {
		return "", err
	}
	// Revert reader position
	if _, err := reader.Seek(currPos, io.SeekStart); err != nil {
		return "", err
	}
	return res, nil
}

func NewQuery(domainName string, recordType uint16) ([]byte, error) {
	var err error
	name, err := EncodeDomainName(domainName)
	if err != nil {
		return nil, err
	}
	id := rand.Intn(2<<15 - 1)
	header := DNSHeader{
		Id:           uint16(id),
		Flags:        0,
		NumQuestions: 1,
	}
	question := DNSQuestion{
		Name:  name,
		Type:  recordType,
		Class: ClassIn,
	}
	var payload bytes.Buffer
	payload.Write(header.Bytes())
	payload.Write(question.Bytes())
	return payload.Bytes(), nil
}

func SendQuery(ipAddr string, domainName string, recordType int) (*DNSPacket, error) {
	query, err := NewQuery(domainName, uint16(recordType))
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP(ipAddr),
		Port: 53,
	})
	if err != nil {
		return nil, err
	}
	if _, err = conn.Write(query); err != nil {
		_ = conn.Close() // Write error takes precedence
		return nil, err
	}

	b := make([]byte, 1024)
	if _, err = conn.Read(b); err != nil {
		return nil, err
	}
	if err = conn.Close(); err != nil {
		return nil, err
	}
	reader := bytes.NewReader(b)
	var packet DNSPacket
	if err := packet.FromBytes(reader); err != nil {
		return nil, err
	}
	return &packet, nil
}

func getIPFromRecords(records *[]DNSRecord) string {
	for _, answer := range *records {
		if answer.Type == TypeA {
			data := answer.Data
			return net.IPv4(data[0], data[1], data[2], data[3]).String()
		}
	}
	return ""
}

func getNameServer(packet *DNSPacket) string {
	for _, authority := range *packet.Authorities {
		if authority.Type == TypeNS {
			return string(authority.Data)
		}
	}
	return ""
}

func Resolve(domainName string, recordType int) (string, error) {
	nameServer := "198.41.0.4"
	for {
		fmt.Printf("Querying %s for %s\n", nameServer, domainName)
		resp, err := SendQuery(nameServer, domainName, recordType)
		if err != nil {
			return "", err
		}
		if ip := getIPFromRecords(resp.Answers); ip != "" {
			return ip, nil
		}
		if ip := getIPFromRecords(resp.Additionals); ip != "" {
			nameServer = ip
			continue
		}
		if nsDomain := getNameServer(resp); nsDomain != "" {
			nameServer, err = Resolve(nsDomain, TypeA)
			if err != nil {
				return "", err
			}
			continue
		}
		return "", errors.New("failed to extract IP information")
	}
}
