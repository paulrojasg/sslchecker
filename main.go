package main

import (
	"flag"
	"fmt"
	"os"
	"paulrojasg/sslchecker/scanner"
)

func main() {

	verboseParameter := flag.Bool("verbose", false, "Include extra details in summary report")
	flag.Parse()

	tailArgs := flag.Args()

	if len(tailArgs) != 1 {
		fmt.Println("usage: sslcheck <host>")
		os.Exit(1)
	}

	host := tailArgs[0]

	scanner.ScanDomain(host, *verboseParameter)
}
