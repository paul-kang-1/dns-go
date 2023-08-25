package cmd

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/paul-kang-1/dns-go/dns"
	"github.com/spf13/cobra"
)

var nameServer string
var batchFileName string

var rootCmd = &cobra.Command{
	Use:   "dns-go",
	Short: "A minimal tool for querying DNS name servers",
	Args: func(cmd *cobra.Command, args []string) error {
		var err error
		if len(args) > 1 || (len(args) == 0 && batchFileName == "") {
			err = errors.New("either a target domain name or a filename should be supplied")
		} else if len(args) == 1 && batchFileName != "" {
			err = errors.New("only one of target domain name or filename should be supplied")
		} else if len(args) == 1 {
			_, err = url.Parse(args[0])
		} else if batchFileName != "" {
			_, err = os.Stat(batchFileName)
		}
		return err
	},
	Run: func(cmd *cobra.Command, args []string) {
		done := make(chan struct{}, 1)
		if batchFileName == "" {
			go func() {
				ip, err := dns.Resolve(nameServer, args[0], dns.TypeA)
				if err != nil {
					log.Fatal(err)
				}
				fmt.Println(ip)
				close(done)
			}()
		} else {
			go func() {
				data, err := os.ReadFile(batchFileName)
				if err != nil {
					log.Fatal(err)
				}
				domainList := strings.Split(string(data), "\n")
				ipList, err := dns.ResolveBatch(nameServer, domainList, dns.TypeA)
				if err != nil {
					log.Fatal(err)
				}
				for i, ip := range ipList {
					fmt.Printf("Retrieved IP for %s: %s\n", domainList[i], ip)
				}
				close(done)
			}()
		}
		select {
		case <-time.After(5 * time.Second):
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
	rootCmd.PersistentFlags().StringVar(&batchFileName, "file", "", "A file containing a newline-separated list of domain names to query")
}
