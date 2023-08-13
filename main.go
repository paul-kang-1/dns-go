package main

import (
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
}
