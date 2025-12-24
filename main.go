package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"paulrojasg/sslchecker/domain"
	"paulrojasg/sslchecker/scanner"
	"time"
)

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

	flag.Parse()

	if err := validateParameters(&scanParameters); err != nil {
		fmt.Println("Error:", err)
		fmt.Println("Usage: sslcheck [options] <hosts>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	hosts := flag.Args()
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
