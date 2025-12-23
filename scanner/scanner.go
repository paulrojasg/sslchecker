package scanner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"paulrojasg/sslchecker/domain"
	"paulrojasg/sslchecker/formatter"
	"paulrojasg/sslchecker/ssllabs"
	"time"
)

func analyzeWithRetry(
	ctx context.Context,
	client *ssllabs.Client,
	host string,
	parameters domain.ScanParameters,
) (*domain.HostReport, error) {

	const maxRetries = 3
	const delaySeconds = 3
	const retryDelay = delaySeconds * time.Second

	for attempt := 1; attempt <= maxRetries; attempt++ {

		report, err := client.Analyze(ctx, host, parameters)
		if err != nil {
			var apiErr *domain.APIError

			if errors.As(err, &apiErr) {
				switch apiErr.StatusCode {
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
				}
				continue
			}
			fmt.Printf("[!] Error: Failed to refresh data: %v", err)
			time.Sleep(retryDelay)
		}
		return report, err
	}
	return nil, fmt.Errorf("Maximum retries limit reached")
}

// TODO: Show maximum and current number of assessments in verbose mode
func ScanDomain(host string, parameters *domain.ScanParameters) error {

	verbose := parameters.Verbose

	client := ssllabs.NewClient()

	var ctx context.Context
	var cancelCtx context.CancelFunc
	if parameters.Timeout > 0 {
		timeoutLimit := time.Duration(parameters.Timeout) * time.Second
		ctx, cancelCtx = context.WithTimeout(context.Background(), timeoutLimit)
		if verbose {
			fmt.Printf("[INFO] Global timeout: %s", timeoutLimit)
		}
	} else {
		ctx, cancelCtx = context.WithCancel(context.Background())
		if verbose {
			fmt.Printf("[INFO] Global timeout disabled")
		}
	}

	defer cancelCtx()

	startTime := time.Now()

	report, err := analyzeWithRetry(ctx, client, host, *parameters)
	if err != nil {
		return fmt.Errorf("Failed to initiate scan for %s: %v", host, err)
	}

	tickerDelaySeconds := 10 * time.Second
	previousStatus := report.Status

	fmt.Printf("\n>>> Target: %s\n", host)
	fmt.Printf("[STATUS] %-12s (Initial Check)\n", previousStatus)

	switch previousStatus {
	case domain.StatusDNS:
		tickerDelaySeconds = 5 * time.Second
	case domain.StatusInProgress:
		fmt.Printf("[INFO]   Detected %d endpoints\n", len(report.Endpoints))
		formatter.PrintEndpointProgress(*report, *parameters)
	case domain.StatusReady:
		formatter.PrintHostSummary(*report, parameters.Verbose)
		return nil
	case domain.StatusError:
		return fmt.Errorf("%s", report.StatusMessage)
	default:
		return fmt.Errorf("Unexpected status: %s", previousStatus)
	}

	parameters.New = false

	ticker := time.NewTicker(tickerDelaySeconds)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("[!] TIMEOUT: Global time limit reached.")
		case <-ticker.C:
			report, err := analyzeWithRetry(ctx, client, host, *parameters)
			if err != nil {
				return fmt.Errorf("Failed to refresh data: %v", err)
			}

			reportStatus := report.Status
			elapsed := time.Since(startTime).Truncate(time.Second)

			fmt.Printf("\n[STATUS] %-12s | Elapsed: %s", reportStatus, elapsed)

			if reportStatus != previousStatus {
				if reportStatus == domain.StatusInProgress {
					ticker.Reset(10 * time.Second)
					fmt.Printf("\n[INFO]   Endpoints found: %d", len(report.Endpoints))
				}
				previousStatus = reportStatus
			}

			switch reportStatus {
			case domain.StatusDNS:
			case domain.StatusInProgress:
				formatter.PrintEndpointProgress(*report, *parameters)
			case domain.StatusReady:
				formatter.PrintHostSummary(*report, parameters.Verbose)
				return nil
			case domain.StatusError:
				return fmt.Errorf("%s", report.StatusMessage)
			default:
				return fmt.Errorf("Unexpected status: %s", reportStatus)
			}
		}
	}
}
