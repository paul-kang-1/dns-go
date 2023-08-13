package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
)

func main() {
	var err error
	query, err := NewQuery("www.example.com", TYPE_A)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP: net.ParseIP("8.8.8.8"),
		Port: 53,
	})
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(query)
	if err != nil {
		log.Fatal(err)
	}
	b := make([]byte, 1024)
	_, err = conn.Read(b)
	reader := bytes.NewReader(b[12:])
	var header DNSHeader
	if err := header.FromBytes(reader); err != nil {
		log.Fatal(err)
	}
	var question DNSQuestion
	if err := question.FromBytes(reader); err != nil {
		log.Fatal(err)
	}
	var record DNSRecord
	if err := record.FromBytes(reader); err != nil {
		log.Fatal(err)
	}
	fmt.Print(record.TTL)
}
