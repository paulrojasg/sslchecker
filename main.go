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

	err := scanner.ScanDomain(host, *verboseParameter)
	if err != nil {
		fmt.Println("[FATAL]", err)
		os.Exit(1)
	}
	os.Exit(0)
}
