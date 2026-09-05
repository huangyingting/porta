package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type ReadinessCheck struct {
	Name     string
	Required bool
	Probe    func(context.Context) error
}

type ComponentState struct {
	Status   string `json:"status"`
	Required bool   `json:"required"`
	Error    string `json:"error,omitempty"`
}

type ReadinessReport struct {
	Status     string                    `json:"status"`
	Components map[string]ComponentState `json:"components"`
}

type Readiness struct {
	Checks  []ReadinessCheck
	Timeout time.Duration
}

func (r *Readiness) Check(ctx context.Context) ReadinessReport {
	report := ReadinessReport{Status: "not_ready", Components: make(map[string]ComponentState)}
	if r == nil || len(r.Checks) == 0 {
		report.Components["local_forwarding"] = ComponentState{
			Status: "unknown", Required: true, Error: "local forwarding probes are not configured",
		}
		return report
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type result struct {
		name  string
		state ComponentState
	}
	results := make(chan result, len(r.Checks))
	pending := make(map[string]bool)
	required := 0
	for _, check := range r.Checks {
		if check.Required {
			required++
		}
		if check.Probe == nil {
			report.Components[check.Name] = ComponentState{Status: "disabled", Required: check.Required}
			continue
		}
		pending[check.Name] = check.Required
		go func() {
			state := ComponentState{Status: "ok", Required: check.Required}
			if err := check.Probe(ctx); err != nil {
				state.Status, state.Error = "error", err.Error()
			}
			results <- result{check.Name, state}
		}()
	}
	for len(pending) > 0 {
		select {
		case result := <-results:
			report.Components[result.name] = result.state
			delete(pending, result.name)
		case <-ctx.Done():
			for name, required := range pending {
				report.Components[name] = ComponentState{Status: "error", Required: required, Error: ctx.Err().Error()}
				delete(pending, name)
			}
		}
	}
	if required == 0 {
		report.Components["local_forwarding"] = ComponentState{Status: "unknown", Required: true, Error: "no required local forwarding probes"}
		return report
	}
	report.Status = "ready"
	for _, state := range report.Components {
		if state.Required && state.Status != "ok" {
			report.Status = "not_ready"
		}
	}
	return report
}

func (r *Readiness) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	report := r.Check(request.Context())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusOK
	if report.Status != "ready" {
		status = http.StatusServiceUnavailable
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(report)
}
