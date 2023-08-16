package cmd

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/paul-kang-1/dns-go/dns"
	"github.com/spf13/cobra"
)

var nameServer string

var rootCmd = &cobra.Command{
	Use:   "dns-go",
	Short: "A minimal tool for querying DNS name servers",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return errors.New("requires exactly one arg: domain name")
		}
		_, err := url.Parse(args[0])
		if err != nil {
			return errors.New("invalid url format: domain name")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		done := make(chan struct{}, 1)
		go func() {
			ip, err := dns.Resolve(nameServer, args[0], dns.TypeA)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(ip)
			close(done)
		}()
		select {
		case <- time.After(3*time.Second):
			log.Fatal(errors.New("DNS query timeout"))
		case <-done:
			return
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&nameServer, "server", "198.41.0.4", "Name or IP address of the name server to query")
}

