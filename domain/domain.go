package domain

type AssessmentStatus string

type Endpoint struct {
	Grade     string  `json:"grade"`
	IPAddress string  `json:"ipAddress"`
	Progress  float32 `json:"progres"`
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
