package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReadinessReportsUnknownWithoutProbes(t *testing.T) {
	var readiness *Readiness
	recorder := httptest.NewRecorder()
	readiness.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured readiness = %d", recorder.Code)
	}
}

func TestReadinessSeparatesLocalAndExternalHealth(t *testing.T) {
	for _, localFailure := range []bool{false, true} {
		readiness := &Readiness{Checks: []ReadinessCheck{
			{Name: "forwarding", Required: true, Probe: func(context.Context) error {
				if localFailure {
					return errors.New("forwarding disabled")
				}
				return nil
			}},
			{Name: "external_dns", Probe: func(context.Context) error { return errors.New("DNS unavailable") }},
			{Name: "external_egress"},
		}}
		recorder := httptest.NewRecorder()
		readiness.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		wantStatus := http.StatusOK
		if localFailure {
			wantStatus = http.StatusServiceUnavailable
		}
		if recorder.Code != wantStatus {
			t.Fatalf("localFailure=%v readiness=%d", localFailure, recorder.Code)
		}
		var report ReadinessReport
		if err := json.Unmarshal(recorder.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Components["external_dns"].Error != "DNS unavailable" ||
			report.Components["external_egress"].Status != "disabled" {
			t.Fatalf("external probe failures were hidden: %+v", report)
		}
	}
}

func TestReadinessBoundsSlowProbes(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	readiness := &Readiness{Timeout: 20 * time.Millisecond, Checks: []ReadinessCheck{
		{Name: "nat", Required: true, Probe: func(context.Context) error { <-release; return nil }},
	}}
	start := time.Now()
	report := readiness.Check(context.Background())
	if time.Since(start) > time.Second || report.Status != "not_ready" ||
		report.Components["nat"].Error != context.DeadlineExceeded.Error() {
		t.Fatalf("slow probe was not bounded: %+v", report)
	}
}

func TestReadinessDoesNotAcceptOnlyOptionalChecks(t *testing.T) {
	readiness := &Readiness{Checks: []ReadinessCheck{{Name: "external_dns", Probe: func(context.Context) error { return nil }}}}
	if report := readiness.Check(context.Background()); report.Status != "not_ready" {
		t.Fatalf("optional probe falsely established local readiness: %+v", report)
	}
}
