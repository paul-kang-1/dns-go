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
	packet, err := SendQuery("8.8.8.8", domain, TypeA)
	if err != nil {
		log.Fatal(err)
	}
	answers := *packet.Answers
	fmt.Println(answers[0].Data)
}
