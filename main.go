package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"paulrojasg/sslchecker/domain"
	"paulrojasg/sslchecker/scanner"
	"strings"
	"time"
)

func readFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s", err)
	}
	defer file.Close()

	var hosts []string

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		host := scanner.Text()
		if strings.ContainsAny(host, " \t\n\r") {
			fmt.Printf("Reading host '%s' from file failed: Line contains whitespace\n", host)
		} else {
			hosts = append(hosts, host)
		}

	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %s", err)
	}
	return hosts, nil
}

func validateParameters(parameters *domain.ScanParameters) error {
	if all := parameters.All; all != "" && all != "on" && all != "done" {
		return fmt.Errorf("invalid value for 'all' option '%s'. Valid options are: 'on', 'done'", all)
	}
	if parameters.New && parameters.Cache {
		return fmt.Errorf("'cache' option may not be used at the same time as 'new' option")
	}
	if parameters.MaxAge != 0 && !parameters.Cache {
		return fmt.Errorf("'max-age' option must be used along 'cache' option")
	}
	return nil
}

func main() {

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	var scanParameters domain.ScanParameters

	flag.BoolVar(
		&scanParameters.Verbose,
		"verbose",
		false,
		"Show detailed progress information and extended endpoint summaries",
	)

	flag.BoolVar(
		&scanParameters.New,
		"new",
		false,
		"Force a new assessment, ignoring cached results (use only once per scan)",
	)

	flag.BoolVar(
		&scanParameters.Cache,
		"cache",
		false,
		"Use cached assessment results if available instead of waiting for a new scan",
	)

	flag.UintVar(
		&scanParameters.MaxAge,
		"max-age",
		0,
		"Maximum age (in hours) of cached results when used with --cache",
	)

	flag.StringVar(
		&scanParameters.All,
		"all",
		"",
		"Control amount of data returned by the API: 'on' for full data, 'done' for full data only when assessment completes",
	)

	flag.BoolVar(
		&scanParameters.Publish,
		"publish",
		false,
		"Publish assessment results to SSL Labs public results boards",
	)

	flag.BoolVar(
		&scanParameters.IgnoreMismatch,
		"ignore-mismatch",
		false,
		"Proceed with assessment even if certificate hostname does not match the target host",
	)

	flag.UintVar(
		&scanParameters.Timeout,
		"timeout",
		300,
		"Maximum time (in seconds) to wait for the assessment to complete. Use 0 to disable the timeout",
	)

	flag.StringVar(
		&scanParameters.Output,
		"output",
		"",
		"Append raw API responses to file (JSON Lines format)",
	)

	flag.BoolVar(
		&scanParameters.SteadyPolling,
		"steady-polling",
		false,
		"Disable randomized polling intervals (use fixed delays)",
	)

	flag.StringVar(
		&scanParameters.BaseUrl,
		"base-url",
		"https://api.ssllabs.com/api/v2/",
		"Scanning API's base url",
	)

	flag.StringVar(
		&scanParameters.HostsFile,
		"hosts-file",
		"",
		"File path to a host list for scanning. May be combined with hosts supplied as tail arguments.",
	)

	flag.Parse()

	if err := validateParameters(&scanParameters); err != nil {
		fmt.Println("Error:", err)
		fmt.Println("Usage: sslcheck [options] <hosts>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	hosts := flag.Args()

	if file := scanParameters.HostsFile; file != "" {
		if fileHosts, err := readFile(file); err == nil {
			for _, h := range fileHosts {
				hosts = append(hosts, h)
			}
		} else {
			fmt.Println("[FATAL]", err)
			os.Exit(1)
		}
	}

	if len(hosts) == 0 {
		fmt.Println("Usage: sslcheck [options] <hosts>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if err := scanner.ScanHosts(hosts, &scanParameters, rng); err != nil {
		fmt.Println("[FATAL]", err)
		os.Exit(1)
	}

	os.Exit(0)
}
