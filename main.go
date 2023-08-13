package main

import (
	"log"
	"fmt"
)

func main() {
	url := "ad.com"
	res, err := EncodeDomainName(url)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(res)
}
