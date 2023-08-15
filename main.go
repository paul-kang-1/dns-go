package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Type the domain to search: ")
	text, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	domain := strings.TrimSpace(text)
	ip, err := Resolve(domain, TypeA)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ip)
}
