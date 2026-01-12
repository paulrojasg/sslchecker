package scanner

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/paulrojasg/sslchecker/domain"
	"github.com/paulrojasg/sslchecker/formatter"
	"github.com/paulrojasg/sslchecker/ssllabs"
)

type scanState struct {
	parameters *domain.ScanParameters
	rng        *rand.Rand
	ctx        context.Context
	client     *ssllabs.Client
	startTime  time.Time
	scanIndex  int
}

var errGlobalTimeout = errors.New("[!] TIMEOUT: Global time limit reached\n")
var errMaxTriesExceeded = errors.New("Maximum retries limit reached when scanning one of the hosts\n")

// Calculate a random tip of ~20% of the base delay to add after every hit to the API
func calculateTicker(baseDelay int, steadyPolling bool, rng *rand.Rand) time.Duration {
	delay := time.Duration(baseDelay) * time.Second

	if !steadyPolling {
		jitterSeconds := rng.Intn((baseDelay*20)/100) + 1
		delay += time.Duration(jitterSeconds) * time.Second
	}

	return delay
}

// Analyze host one time using API - retrying if it's required
func analyzeWithRetry(
	host string,
	state scanState,
) (*domain.HostReport, error) {
	const maxRetries = 3
	const delaySeconds = 30
	const retryDelay = delaySeconds * time.Second

	ctx := state.ctx
	client := state.client
	parameters := *state.parameters

	for attempt := 1; attempt <= maxRetries; attempt++ {

		report, err := client.Analyze(ctx, host, parameters)
		if err != nil {
			var apiErr *domain.APIError

			if errors.As(err, &apiErr) {
				switch statusCode := apiErr.StatusCode; statusCode {
				case http.StatusTooManyRequests:
					fmt.Printf(
						"[WARN]  Rate limit hit (429). Retrying in %s... (attempt %d/%d)\n",
						retryDelay,
						attempt,
						maxRetries,
					)

					time.Sleep(retryDelay)

				case 529:
					fmt.Printf("[WARN]  API server overloaded (529). Retrying in %s... (attempt %d/%d)\n",
						retryDelay*2,
						attempt,
						maxRetries)
					time.Sleep(retryDelay * 2)
				default:
					fmt.Printf("[WARN]  API server responded with unexpected status code (%d). Retrying in %s... (attempt %d/%d)\n", statusCode, retryDelay*2,
						attempt,
						maxRetries)
					time.Sleep(retryDelay * 2)
				}
				continue
			}
			fmt.Printf("[!] Error: Failed to refresh data: %v", err)
			time.Sleep(retryDelay)
		}
		return report, err
	}
	return nil, errMaxTriesExceeded
}

// Analyze host one time using API - retrying if it's required and with --new = false
func continueAnalyzeWithRetry(
	host string,
	state scanState,
) (*domain.HostReport, error) {

	newParameters := *state.parameters
	newParameters.New = false
	state.parameters = &newParameters
	return analyzeWithRetry(host, state)
}

// Scan a single host - loops until the assessment is complete or the context ends
func scanHost(host string, state scanState) error {
	dnsDelay := 5
	postDnsDelay := 10

	ctxObj := state.ctx
	startTime := state.startTime
	rng := state.rng
	parameters := state.parameters
	scanIndex := state.scanIndex

	steadyPolling := parameters.SteadyPolling

	report, err := analyzeWithRetry(host, state)
	if err != nil {
		return fmt.Errorf("Failed to initiate scan for %s: %w", host, err)
	}

	tickerDelaySeconds := postDnsDelay
	previousStatus := report.Status

	fmt.Printf("\n>>> Target: %d (%s)\n", scanIndex, host)
	fmt.Printf("[STATUS] %-12s (Initial Check)\n", previousStatus)

	switch previousStatus {
	case domain.StatusDNS:
		tickerDelaySeconds = dnsDelay
	case domain.StatusInProgress:
		fmt.Printf("[INFO]   Detected %d endpoints\n", len(report.Endpoints))
		formatter.PrintEndpointProgress(*report, parameters)
	case domain.StatusReady:
		formatter.PrintHostSummary(*report, parameters)
		if parameters.Output != "" {
			if err := formatter.WriteRawJSONFile(report, parameters); err != nil {
				return fmt.Errorf("Error while writing into file: %s", err)
			}
		}
		return nil
	case domain.StatusError:
		return fmt.Errorf("%s\n", report.StatusMessage)
	default:
		return fmt.Errorf("Unexpected status: %s\n", previousStatus)
	}

	ticker := time.NewTicker(calculateTicker(tickerDelaySeconds, steadyPolling, rng))
	defer ticker.Stop()

	for {
		select {
		case <-ctxObj.Done():
			return errGlobalTimeout
		case <-ticker.C:
			report, err := continueAnalyzeWithRetry(host, state)
			if err != nil {
				return fmt.Errorf("Failed to initiate scan for %s: %w", host, err)
			}

			reportStatus := report.Status
			elapsed := time.Since(startTime).Truncate(time.Second)

			fmt.Printf("\n[STATUS] %-12s | Elapsed: %s", reportStatus, elapsed)

			if reportStatus != previousStatus {
				if reportStatus == domain.StatusInProgress {
					tickerDelaySeconds = postDnsDelay
					fmt.Printf("\n[INFO]   Endpoints found: %d", len(report.Endpoints))
				}
				previousStatus = reportStatus
			}

			switch reportStatus {
			case domain.StatusDNS:
			case domain.StatusInProgress:
				formatter.PrintEndpointProgress(*report, parameters)
			case domain.StatusReady:
				formatter.PrintHostSummary(*report, parameters)
				if parameters.Output != "" {
					if err := formatter.WriteRawJSONFile(report, parameters); err != nil {
						return fmt.Errorf("Error while writing into file: %s", err)
					}
				}
				return nil
			case domain.StatusError:
				return fmt.Errorf("%s", report.StatusMessage)
			default:
				return fmt.Errorf("Unexpected status: %s", reportStatus)
			}
			ticker.Reset(calculateTicker(tickerDelaySeconds, steadyPolling, rng))
		}
	}
}

// Scan list of hosts
func ScanHosts(hosts []string, parameters *domain.ScanParameters, rng *rand.Rand) error {

	verbose := parameters.Verbose

	client := ssllabs.NewClient(parameters.BaseUrl)

	var ctx context.Context
	var cancelCtx context.CancelFunc
	if parameters.Timeout > 0 {
		timeoutLimit := time.Duration(parameters.Timeout) * time.Second
		ctx, cancelCtx = context.WithTimeout(context.Background(), timeoutLimit)
		if verbose {
			fmt.Printf("[INFO] Global timeout: %s\n", timeoutLimit)
		}
	} else {
		ctx, cancelCtx = context.WithCancel(context.Background())
		if verbose {
			fmt.Printf("[INFO] Global timeout disabled\n")
		}
	}

	defer cancelCtx()

	startTime := time.Now()

	failedHosts := []string{}

	for ind, host := range hosts {
		state := scanState{
			parameters: parameters,
			rng:        rng,
			ctx:        ctx,
			client:     client,
			startTime:  startTime,
			scanIndex:  ind + 1,
		}
		if err := scanHost(host, state); err != nil {
			failedHosts = append(failedHosts, host)
			if errors.Is(err, errMaxTriesExceeded) || errors.Is(err, errGlobalTimeout) {
				return fmt.Errorf("%w", err)
			} else {
				fmt.Printf("Scan failed on host %s", err)
			}
		}
	}
	if len(failedHosts) > 0 {
		fmt.Println()
		fmt.Println("Scan on the following hosts failed:")
		for _, host := range failedHosts {
			fmt.Printf(" - %s\n", host)
		}
		return fmt.Errorf("One or more scans failed")
	}
	return nil
}
