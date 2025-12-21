package formatter

import (
	"fmt"
	"paulrojasg/sslchecker/domain"
)

func PrintHostSummary(report domain.HostReport) {
	fmt.Println("-- ASSESSMENT HOST REPORT SUMMARY --")
	fmt.Println("Host:", report.Host)
	fmt.Println("Endpoints:")

	if len(report.Endpoints) == 0 {
		fmt.Println("  (none)")
		return
	}

	for i, endpoint := range report.Endpoints {
		fmt.Printf(
			"  Endpoint %d - %s: %s\n",
			i+1,
			endpoint.IPAddress,
			endpoint.Grade,
		)
	}
}
