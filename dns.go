package main

import (
	"bytes"
	"strings"
)

type (
	DNSHeader struct {
		Id                                                       uint16
		Flags                                                    uint16
		NumQuestions, NumAnswers, NumAuthorities, NumAdditionals uint16
	}

	DNSQuestion struct {
		Name  string
		Type  uint16
		Class uint16
	}
)

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
	// Mark termination with zero byte
	err = buf.WriteByte(byte(0))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
