package main

import (
	"bytes"
	"encoding/binary"
	"io"

	"math/rand"
	"strings"
)

type (
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
		Questions   []*DNSQuestion
		Answers     []*DNSRecord
		Authorities []*DNSRecord
		Additionals []*DNSRecord
	}
)

const (
	// Header options
	RECURSION_DESIRED = uint16(1 << 8)

	// Record types
	TYPE_A = 1

	// Classes
	CLASS_IN = 1
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
	if err := binary.Read(reader, binary.BigEndian, &dh.Id); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &dh.Flags); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &dh.NumQuestions); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &dh.NumAnswers); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &dh.NumAuthorities); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &dh.NumAdditionals); err != nil {
		return err
	}
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
	if err := binary.Read(reader, binary.BigEndian, &dq.Type); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &dq.Class); err != nil {
		return err
	}
	return nil
}

// FromBytes creates a DNSRecord from the given sequence of bytes.
// Refer to Section 4.1.3 (Resource Record Format) of RFC 1035.
func (dr *DNSRecord) FromBytes(reader *bytes.Reader) error {
	name, err := DecodeDomainName(reader)
	if err != nil {
		return err
	}
	dr.Name = []byte(name)
	if err := binary.Read(reader, binary.BigEndian, &dr.Type); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &dr.Class); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &dr.TTL); err != nil {
		return err
	}
	var readLen uint16
	if err := binary.Read(reader, binary.BigEndian, &readLen); err != nil {
		return err
	}
	dr.Data = make([]byte, readLen)
	if _, err := io.ReadFull(reader, dr.Data); err != nil {
		return err
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
			return DecodeDomainNameCompressed(length, reader)
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
		Flags:        RECURSION_DESIRED,
		NumQuestions: 1,
	}
	question := DNSQuestion{
		Name:  name,
		Type:  recordType,
		Class: CLASS_IN,
	}
	var payload bytes.Buffer
	payload.Write(header.Bytes())
	payload.Write(question.Bytes())
	return payload.Bytes(), nil
}
