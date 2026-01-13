package scanner

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/paulrojasg/sslchecker/domain"
	"github.com/paulrojasg/sslchecker/formatter"
	"github.com/paulrojasg/sslchecker/ssllabs"
)

type scanState struct {
	parameters *domain.ScanParameters
	rng        *rand.Rand
	client     *ssllabs.Client
	startTime  time.Time
	scanIndex  int
	controller *AssessmentController
}
type AssessmentController struct {
	sem     chan struct{}
	pauseCh chan struct{}
	mu      sync.Mutex

	ctx    context.Context
	cancel context.CancelFunc
}

type Host struct {
	host       string
	raiseError bool
}

func NewAssessmentController(max int, ctx context.Context, cancel context.CancelFunc) *AssessmentController {

	c := &AssessmentController{
		sem:     make(chan struct{}, max),
		pauseCh: make(chan struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}
	close(c.pauseCh) // start unpaused
	return c
}

func (c *AssessmentController) Kill() {
	c.cancel() // cancel context
	c.Resume() // unblock paused goroutines
}

func (c *AssessmentController) Pause() {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.pauseCh:
		c.pauseCh = make(chan struct{}) // RED LIGHT
	default:
	}
}

func (c *AssessmentController) Resume() {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.pauseCh:
		// already resumed
	default:
		close(c.pauseCh)
	}
}

func (c *AssessmentController) Acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *AssessmentController) Release() {
	select {
	case <-c.sem:
	default:
	}
}

var ErrTooManyRequests = errors.New("429 too many requests")

var errMaxTriesExceeded = errors.New("Maximum retries limit reached when scanning one of the hosts\n")

func calculateTicker(baseDelay int, steadyPolling bool, rng *rand.Rand) time.Duration {
	delay := time.Duration(baseDelay) * time.Second

	if !steadyPolling {
		jitterSeconds := rng.Intn((baseDelay*20)/100) + 1
		delay += time.Duration(jitterSeconds) * time.Second
	}

	return delay
}

func analyzeWithRetry(
	host string,
	state scanState,
	logger *domain.AsyncLogger,
) (*domain.HostReport, error) {
	const maxRetries = 3
	const delaySeconds = 3
	const retryDelay = delaySeconds * time.Second

	ctx := state.controller.ctx
	client := state.client
	parameters := *state.parameters

	select {
	case <-state.controller.pauseCh:
	case <-state.controller.ctx.Done():
		return nil, fmt.Errorf("[!] Context cancelled")
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {

		report, err := client.Analyze(ctx, host, parameters)
		if err != nil {
			var apiErr *domain.APIError

			if errors.As(err, &apiErr) {
				switch statusCode := apiErr.StatusCode; statusCode {
				case http.StatusTooManyRequests:
					logger.Printf(host,
						"[WARN]  Rate limit hit (429). Retrying in %s... (attempt %d/%d)\n",
						retryDelay,
						attempt,
						maxRetries,
					)

					state.controller.Pause()
					time.Sleep(retryDelay)

				case 529:
					logger.Printf(host, "[WARN]  API server overloaded (529). Retrying in %s... (attempt %d/%d)\n",
						retryDelay*2,
						attempt,
						maxRetries)
					state.controller.Pause()
					time.Sleep(retryDelay * 2)
				default:
					logger.Printf(host, "[WARN]  API server responded with unexpected status code (%d). Retrying in %s... (attempt %d/%d)\n", statusCode, retryDelay*2,
						attempt,
						maxRetries)
					state.controller.Pause()
					time.Sleep(retryDelay * 2)
				}
				continue
			}
			logger.Printf(host, "[!] Error: Failed to refresh data: %v\n", err)
			time.Sleep(retryDelay)
		}
		state.controller.Resume()
		return report, err
	}
	state.controller.Kill()
	return nil, errMaxTriesExceeded
}

func continueAnalyzeWIthRetry(
	host string,
	state scanState,
	logger *domain.AsyncLogger,
) (*domain.HostReport, error) {

	newParameters := *state.parameters
	newParameters.New = false
	state.parameters = &newParameters
	return analyzeWithRetry(host, state, logger)
}

func scanHost(host string, state scanState, logger *domain.AsyncLogger) error {
	dnsDelay := 5
	postDnsDelay := 10

	ctxObj := state.controller.ctx
	startTime := state.startTime
	rng := state.rng
	parameters := state.parameters
	scanIndex := state.scanIndex

	steadyPolling := parameters.SteadyPolling

	report, err := analyzeWithRetry(host, state, logger)
	if err != nil {
		return fmt.Errorf("Failed to initiate scan for %s: %w", host, err)
	}

	tickerDelaySeconds := postDnsDelay
	previousStatus := report.Status

	logger.Printf(host, ">>> Target: %d (%s)\n", scanIndex, host)
	logger.Printf(host, "[STATUS] %-12s (Initial Check)\n", previousStatus)

	switch previousStatus {
	case domain.StatusDNS:
		tickerDelaySeconds = dnsDelay
	case domain.StatusInProgress:
		logger.Printf(host, "[INFO]   Detected %d endpoints\n", len(report.Endpoints))
		formatter.PrintEndpointProgress(report, parameters, logger)
	case domain.StatusReady:
		formatter.PrintHostSummary(report, parameters, logger)
		if parameters.Output != "" {
			if err := formatter.WriteRawJSONFile(report, parameters, logger); err != nil {
				return fmt.Errorf("Error while writing into file: %s", err)
			}
		}
		return nil
	case domain.StatusError:
		return fmt.Errorf("%s\n", report.StatusMessage)
	default:
		return fmt.Errorf("Unexpected status: %s\n", previousStatus)
	}

	ticker := time.NewTicker(calculateTicker(tickerDelaySeconds, steadyPolling, rng))
	defer ticker.Stop()

	for {
		select {
		case <-state.controller.pauseCh:
		case <-ctxObj.Done():
			return fmt.Errorf("[!] Context cancelled")
		}

		select {
		case <-ctxObj.Done():
			return fmt.Errorf("[!] TIMEOUT: Global time limit reached.")
		case <-ticker.C:
			report, err := continueAnalyzeWIthRetry(host, state, logger)
			if err != nil {
				return fmt.Errorf("Failed to initiate scan for %s: %w", host, err)
			}

			reportStatus := report.Status
			elapsed := time.Since(startTime).Truncate(time.Second)

			logger.Printf(host, "[STATUS] %-12s | Elapsed: %s\n", reportStatus, elapsed)

			if reportStatus != previousStatus {
				if reportStatus == domain.StatusInProgress {
					tickerDelaySeconds = postDnsDelay
					logger.Printf(host, "[INFO]   Endpoints found: %d\n", len(report.Endpoints))
				}
				previousStatus = reportStatus
			}

			switch reportStatus {
			case domain.StatusDNS:
			case domain.StatusInProgress:
				formatter.PrintEndpointProgress(report, parameters, logger)
			case domain.StatusReady:
				formatter.PrintHostSummary(report, parameters, logger)
				if parameters.Output != "" {
					if err := formatter.WriteRawJSONFile(report, parameters, logger); err != nil {
						return fmt.Errorf("Error while writing into file: %s", err)
					}
				}
				return nil
			case domain.StatusError:
				return fmt.Errorf("%s", report.StatusMessage)
			default:
				return fmt.Errorf("Unexpected status: %s", reportStatus)
			}
			ticker.Reset(calculateTicker(tickerDelaySeconds, steadyPolling, rng))
		}
	}
}

func ScanHosts(hosts []string, parameters *domain.ScanParameters, rng *rand.Rand) error {

	verbose := parameters.Verbose
	parallel := parameters.Parallel

	client := ssllabs.NewClient(parameters.BaseUrl)

	var ctx context.Context
	var cancelCtx context.CancelFunc
	if parameters.Timeout > 0 {
		timeoutLimit := time.Duration(parameters.Timeout) * time.Second
		ctx, cancelCtx = context.WithTimeout(context.Background(), timeoutLimit)
		if verbose {
			fmt.Printf("[INFO] Global timeout: %s\n", timeoutLimit)
		}
	} else {
		ctx, cancelCtx = context.WithCancel(context.Background())
		if verbose {
			fmt.Printf("[INFO] Global timeout disabled\n")
		}
	}

	defer cancelCtx()

	startTime := time.Now()

	var maxParallel int

	if parallel {
		if parameters.MaxParallel == 0 {
			maxParallel = len(hosts)
		} else {
			maxParallel = int(parameters.MaxParallel)
		}
	} else {
		maxParallel = 1
	}

	controller := NewAssessmentController(maxParallel, ctx, cancelCtx)
	logger := domain.NewAsyncLogger(100)
	var wg sync.WaitGroup

	errCh := make(chan error, len(hosts))

	for ind, host := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()

			if err := controller.Acquire(controller.ctx); err != nil {
				return
			}
			defer controller.Release()

			select {
			case <-controller.pauseCh:
			case <-controller.ctx.Done():
				return
			}
			state := scanState{
				parameters: parameters,
				rng:        rng,
				controller: controller,
				client:     client,
				startTime:  startTime,
				scanIndex:  ind + 1,
			}
			if err := scanHost(host, state, logger); err != nil {
				errCh <- err
				if errors.Is(err, errMaxTriesExceeded) {
					controller.Kill()
				}
			}
		}(host)
		if parallel {
			time.Sleep(3 * time.Second)
		}
	}
	wg.Wait()
	logger.Close()
	close(errCh)
	if len(errCh) > 0 {
		err := <-errCh
		fmt.Printf("%s\n", err)
	}
	return nil
}
