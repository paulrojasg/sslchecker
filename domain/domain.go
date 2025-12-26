package domain

import (
	"fmt"
	"sync"
)

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
	RawJSON       []byte           `json:"-"`
}

type ScanParameters struct {
	Verbose        bool
	New            bool
	Cache          bool
	MaxAge         uint
	All            string
	Publish        bool
	IgnoreMismatch bool
	Timeout        uint
	Output         string
	SteadyPolling  bool
	BaseUrl        string
	HostsFile      string
	Parallel       bool
	MaxParallel    uint
}

type AsyncLogger struct {
	logChan chan string
	mu      sync.Mutex
	wg      sync.WaitGroup
}

type LogSession struct {
	logger *AsyncLogger
	host   string
}

func (l *AsyncLogger) Begin(host string) *LogSession {
	l.mu.Lock()
	return &LogSession{
		logger: l,
		host:   host,
	}
}

func (s *LogSession) End() {
	s.logger.mu.Unlock()
}

func (s *LogSession) Printf(format string, a ...any) {
	s.logger.logChan <- fmt.Sprintf(
		"[ %s ] | %s",
		s.host,
		fmt.Sprintf(format, a...),
	)
}

func (s *LogSession) Println(a ...any) {
	s.logger.logChan <- fmt.Sprintf(
		"[ %s ] | %s",
		s.host,
		fmt.Sprintln(a...),
	)
}

func (l *AsyncLogger) Close() {
	close(l.logChan)
	l.wg.Wait()
}

func (l *AsyncLogger) Printf(host, format string, a ...any) {
	l.logChan <- fmt.Sprintf(
		"[ %s ] | %s",
		host,
		fmt.Sprintf(format, a...),
	)
}

func (l *AsyncLogger) Println(host string, a ...any) {
	l.logChan <- fmt.Sprintf(
		"[ %s ] | %s",
		host,
		fmt.Sprintln(a...),
	)
}

func NewAsyncLogger(bufferSize int) *AsyncLogger {
	l := &AsyncLogger{
		logChan: make(chan string, bufferSize),
	}

	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		for msg := range l.logChan {
			fmt.Print(msg)
		}
	}()

	return l
}

const (
	StatusDNS        AssessmentStatus = "DNS"
	StatusInProgress AssessmentStatus = "IN_PROGRESS"
	StatusReady      AssessmentStatus = "READY"
	StatusError      AssessmentStatus = "ERROR"
)
