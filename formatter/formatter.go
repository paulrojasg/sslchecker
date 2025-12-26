package formatter

import (
	"fmt"
	"os"
	"paulrojasg/sslchecker/domain"
	"strings"
	"sync"
	"time"
)

var fileLock sync.Mutex

func WriteRawJSONFile(report *domain.HostReport, parameters *domain.ScanParameters, logger *domain.AsyncLogger) error {
	fileLock.Lock()
	defer fileLock.Unlock()
	file, err := os.OpenFile(
		parameters.Output,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(report.RawJSON); err != nil {
		return err
	}

	if _, err := file.Write([]byte("\n")); err != nil {
		return err
	}
	if parameters.Verbose {
		logger.Printf(report.Host, "[INFO] Raw API response saved to %s\n", parameters.Output)
	}

	return nil
}

func PrintEndpointProgress(report *domain.HostReport, parameters *domain.ScanParameters, logger *domain.AsyncLogger) {
	session := logger.Begin(report.Host)
	defer session.End()

	readyEndpoints := 0
	for _, endpoint := range report.Endpoints {
		if int(endpoint.Progress) == 100 {
			readyEndpoints++
		}
	}

	timestamp := time.Now().Format("15:04:05")

	// Always show global progress
	session.Printf(
		"[%s] ASSESSMENT PROGRESS: %d/%d COMPLETE\n",
		timestamp,
		readyEndpoints,
		len(report.Endpoints),
	)

	// Stop here if not verbose
	if !parameters.Verbose {
		return
	}

	// Verbose: detailed endpoint progress
	session.Println(strings.Repeat("-", 60))

	for _, endpoint := range report.Endpoints {
		progress := max(int(endpoint.Progress), 0)

		status := "  PENDING  "
		inProgress := false

		switch {
		case progress >= 100:
			status = "   READY   "
		case endpoint.StatusDetailsMessage != "":
			status = "IN PROGRESS"
			inProgress = true
		}

		var statusDetailsMessage string

		if inProgress {
			statusDetailsMessage = fmt.Sprintf(" | %s\n", endpoint.StatusDetailsMessage)
		} else {
			statusDetailsMessage = "\n"
		}

		session.Printf(
			"  [%-11s] %3d%%  → %s%s",
			status,
			progress,
			endpoint.IPAddress,
			statusDetailsMessage,
		)

	}
}

func PrintHostSummary(report *domain.HostReport, parameters *domain.ScanParameters, logger *domain.AsyncLogger) {
	session := logger.Begin(report.Host)
	defer session.End()

	session.Println(strings.Repeat("=", 60))
	session.Println("FINAL ASSESSMENT SUMMARY")
	session.Printf("Target Host: %s\n", report.Host)
	session.Println(strings.Repeat("=", 60))

	if len(report.Endpoints) == 0 {
		session.Println("  (No endpoints analyzed)")
		return
	}

	session.Printf("  %-8s  %-15s\n", "GRADE", "IP ADDRESS")
	session.Println("  " + strings.Repeat("-", 25))

	for _, endpoint := range report.Endpoints {
		session.Printf("  %-8s  %-15s",
			"["+endpoint.Grade+"]",
			endpoint.IPAddress,
		)
		if endpoint.Grade == "" {
			session.Printf(" | %s\n", endpoint.StatusMessage)
		} else {
			session.Println()
		}
	}

	if parameters.Verbose {
		session.Println("DETAILED ENDPOINT SPECIFICATIONS")
		session.Println(strings.Repeat("-", 60))

		for i, ep := range report.Endpoints {
			serverName := ep.ServerName

			if serverName == "" {
				serverName = "(Not specified)"
			}

			session.Printf("[%d] IP Address: %s\n", i+1, ep.IPAddress)
			session.Printf("    Grade:           %s\n", ep.Grade)
			session.Printf("    Trust Ignored:   %s\n", ep.GradeTrustIgnored)
			session.Printf("    Has Warnings:    %t\n", ep.HasWarnings)
			session.Printf("    Is Exceptional:  %t\n", ep.IsExceptional)
			session.Printf("    Server Name:     %s\n", serverName)
			session.Printf("    Delegation:      %d\n", ep.Delegation)
			session.Println("    " + strings.Repeat(".", 20))
		}
	}

	session.Println(strings.Repeat("-", 60))
	session.Printf("Total Endpoints: %d\n\n", len(report.Endpoints))
}
