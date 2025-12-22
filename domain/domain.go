package domain

type AssessmentStatus string

type Endpoint struct {
	Grade             string `json:"grade"`
	IPAddress         string `json:"ipAddress"`
	Progress          int    `json:"progress"`
	GradeTrustIgnored string `json:"gradeTrustIgnored"`
	HasWarnings       bool   `json:"hasWarnings"`
	IsExceptional     bool   `json:"isExceptional"`
	ServerName        string `json:"serverName"`
	Delegation        int    `json:"delegation"`
}

type HostReport struct {
	Host          string           `json:"host"`
	Status        AssessmentStatus `json:"status"`
	StatusMessage string           `json:"statusMessage"`
	Endpoints     []Endpoint       `json:"endpoints"`
}

const (
	StatusDNS        AssessmentStatus = "DNS"
	StatusInProgress AssessmentStatus = "IN_PROGRESS"
	StatusReady      AssessmentStatus = "READY"
	StatusError      AssessmentStatus = "ERROR"
)
