package main

import (
	"bytes"
	"encoding/binary"

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
	binary.BigEndian.PutUint16(res[0:], dh.Id)
	binary.BigEndian.PutUint16(res[2:], dh.Flags)
	binary.BigEndian.PutUint16(res[4:], dh.NumQuestions)
	binary.BigEndian.PutUint16(res[6:], dh.NumAnswers)
	binary.BigEndian.PutUint16(res[8:], dh.NumAuthorities)
	binary.BigEndian.PutUint16(res[10:], dh.NumAdditionals)
	return res
}

func (dq *DNSQuestion) Bytes() []byte {
	res := make([]byte, 4)
	binary.BigEndian.PutUint16(res[0:], dq.Type)
	binary.BigEndian.PutUint16(res[2:], dq.Class)
	return append(dq.Name, res...)
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
