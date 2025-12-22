package formatter

import (
	"fmt"
	"paulrojasg/sslchecker/domain"
	"strings"
	"time"
)

func PrintEndpointProgress(report domain.HostReport) {
	readyEndpoints := 0
	for _, endpoint := range report.Endpoints {
		if int(endpoint.Progress) == 100 {
			readyEndpoints++
		}
	}

	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("\n[%s] ASSESSMENT PROGRESS: %d/%d COMPLETE\n", timestamp, readyEndpoints, len(report.Endpoints))
	fmt.Println(strings.Repeat("-", 60))

	for _, endpoint := range report.Endpoints {

		progress := int(endpoint.Progress)

		status := "PENDING"

		if progress >= 100 {
			status = " DONE  "
		} else if progress == -1 {
			progress = 0
		}
		fmt.Printf("  [%s] %3d%%  → %s\n", status, progress, endpoint.IPAddress)
	}
}

func PrintHostSummary(report domain.HostReport, verbose bool) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("FINAL ASSESSMENT SUMMARY")
	fmt.Printf("Target Host: %s\n", report.Host)
	fmt.Println(strings.Repeat("=", 60))

	if len(report.Endpoints) == 0 {
		fmt.Println("  (No endpoints analyzed)")
		return
	}

	fmt.Printf("  %-8s  %-15s\n", "GRADE", "IP ADDRESS")
	fmt.Println("  " + strings.Repeat("-", 25))

	for _, endpoint := range report.Endpoints {
		fmt.Printf("  %-8s  %-15s\n",
			"["+endpoint.Grade+"]",
			endpoint.IPAddress,
		)
	}

	if verbose {
		fmt.Println("\nDETAILED ENDPOINT SPECIFICATIONS")
		fmt.Println(strings.Repeat("-", 60))

		for i, ep := range report.Endpoints {
			serverName := ep.ServerName

			if serverName == "" {
				serverName = "(Not specified)"
			}

			fmt.Printf("[%d] IP Address: %s\n", i+1, ep.IPAddress)
			fmt.Printf("    Grade:           %s\n", ep.Grade)
			fmt.Printf("    Trust Ignored:   %s\n", ep.GradeTrustIgnored)
			fmt.Printf("    Has Warnings:    %t\n", ep.HasWarnings)
			fmt.Printf("    Is Exceptional:  %t\n", ep.IsExceptional)
			fmt.Printf("    Server Name:     %s\n", serverName)
			fmt.Printf("    Delegation:      %d\n", ep.Delegation)
			fmt.Println("    " + strings.Repeat(".", 20))
		}
	}

	fmt.Println(strings.Repeat("-", 60))
	fmt.Printf("Total Endpoints: %d\n\n", len(report.Endpoints))
}
