package domain

import "fmt"

type AssessmentStatus string

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("api error (%d): %s", e.StatusCode, e.Message)
}

type Endpoint struct {
	Grade                string `json:"grade"`
	IPAddress            string `json:"ipAddress"`
	Progress             int    `json:"progress"`
	GradeTrustIgnored    string `json:"gradeTrustIgnored"`
	HasWarnings          bool   `json:"hasWarnings"`
	IsExceptional        bool   `json:"isExceptional"`
	ServerName           string `json:"serverName"`
	Delegation           int    `json:"delegation"`
	StatusDetailsMessage string `json:"statusDetailsMessage"`
	StatusMessage        string `json:"statusMessage"`
}

type HostReport struct {
	Host          string           `json:"host"`
	Status        AssessmentStatus `json:"status"`
	StatusMessage string           `json:"statusMessage"`
	Endpoints     []Endpoint       `json:"endpoints"`
}

type ScanParameters struct {
	Verbose        bool
	New            bool
	Cache          bool
	MaxAge         uint
	All            string
	Publish        bool
	IgnoreMismatch bool
}

const (
	StatusDNS        AssessmentStatus = "DNS"
	StatusInProgress AssessmentStatus = "IN_PROGRESS"
	StatusReady      AssessmentStatus = "READY"
	StatusError      AssessmentStatus = "ERROR"
)
