# Minimal DNS Lookup Utility in Go
## Running the Program
```sh
go build .
# run dns-go --help for guidance
./dns-go --server 1.1.1.1 www.google.com
```

## System Requirements
- Go >= 1.18 (Use of generics)

## TODO
- [x] Domain name resolution for type A, NS
- [x] Command line interface for DNS lookup
- [ ] Horizontal referral & domain name compression recursion detection
- [ ] UDP server to reply to external DNS queries
