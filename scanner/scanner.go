package scanner

import (
	"context"
	"fmt"
	"paulrojasg/sslchecker/domain"
	"paulrojasg/sslchecker/formatter"
	"paulrojasg/sslchecker/ssllabs"
	"time"
)

func ScanDomain(host string, verbose bool) {
	client := ssllabs.NewClient()
	ctx, cancelCtxTimeout := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancelCtxTimeout()

	startTime := time.Now()

	report, err := client.Analyze(ctx, host, false)
	if err != nil {
		fmt.Printf("[!] Error: Failed to initiate scan for %s: %v\n", host, err)
		return
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
		formatter.PrintEndpointProgress(*report)
	case domain.StatusReady:
		formatter.PrintHostSummary(*report, verbose)
		return
	case domain.StatusError:
		fmt.Printf("[ERROR]  %s\n", report.StatusMessage)
		return
	default:
		fmt.Printf("[ERROR]  Unexpected status: %s\n", previousStatus)
		return
	}

	ticker := time.NewTicker(tickerDelaySeconds)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n[!] TIMEOUT: Global time limit reached.")
			return
		case <-ticker.C:
			report, err := client.Analyze(ctx, host, false)
			if err != nil {
				fmt.Printf("[!] Error: Failed to refresh data: %v\n", err)
				continue
			}

			reportStatus := report.Status
			elapsed := time.Since(startTime).Truncate(time.Second)

			fmt.Printf("\n[STATUS] %-12s | Elapsed: %s\n", reportStatus, elapsed)

			if reportStatus != previousStatus {
				if reportStatus == domain.StatusInProgress {
					ticker.Reset(10 * time.Second)
					fmt.Printf("[INFO]   Endpoints found: %d\n", len(report.Endpoints))
				}
				previousStatus = reportStatus
			}

			switch reportStatus {
			case domain.StatusDNS:
			case domain.StatusInProgress:
				formatter.PrintEndpointProgress(*report)
			case domain.StatusReady:
				formatter.PrintHostSummary(*report, verbose)
				return
			case domain.StatusError:
				fmt.Printf("[ERROR]  %s\n", report.StatusMessage)
				return
			default:
				fmt.Printf("[ERROR]  Unexpected status: %s\n", reportStatus)
				return
			}
		}
	}
}
