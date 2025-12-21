package scanner

import (
	"context"
	"fmt"
	"paulrojasg/sslchecker/domain"
	"paulrojasg/sslchecker/formatter"
	"paulrojasg/sslchecker/ssllabs"
	"time"
)

func ScanDomain(host string) {

	client := ssllabs.NewClient()

	ctx, cancelCtxTimeout := context.WithTimeout(context.Background(), 5*time.Minute)

	defer cancelCtxTimeout()

	startTime := time.Now()

	report, err := client.Analyze(ctx, host, false)
	if err != nil {
		fmt.Println("An error has ocurred scanning the site")
	}

	tickerDelaySeconds := 10 * time.Second
	previousStatus := report.Status

	fmt.Println("Initial assessment status for ", host, ": ", previousStatus)

	switch previousStatus {
	case domain.StatusDNS:
		tickerDelaySeconds = 5 * time.Second
	case domain.StatusInProgress:
		fmt.Printf("%d endpoints found for %s\n", len(report.Endpoints), host)
	case domain.StatusReady:
		formatter.PrintHostSummary(*report)
		return
	case domain.StatusError:
		fmt.Println(report.StatusMessage)
		return
	default:
		fmt.Println("Unknown status error ", previousStatus)
		return
	}

	ticker := time.NewTicker(tickerDelaySeconds)

	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Println("Total time limit reached. Exiting.")
			return
		case <-ticker.C:
			report, err := client.Analyze(ctx, host, false)
			if err != nil {
				fmt.Println("An error has ocurred scanning the site")
			}

			reportStatus := report.Status

			fmt.Printf("Assessment status for %s: (%s) - (%s)\n", host, reportStatus, time.Since(startTime).Truncate(time.Second))

			if reportStatus != previousStatus {
				if reportStatus == domain.StatusInProgress {
					ticker.Reset(10 * time.Second)
					fmt.Printf("%d endpoints found for %s\n", len(report.Endpoints), host)
				}
				previousStatus = reportStatus
			}

			switch reportStatus {
			case domain.StatusDNS:
			case domain.StatusInProgress:
			case domain.StatusReady:
				formatter.PrintHostSummary(*report)
				return
			case domain.StatusError:
				fmt.Println(report.StatusMessage)
				return
			default:
				fmt.Println("Unknown status error ", previousStatus)
				return
			}

		}
	}
}
