package hostset

import (
	"strings"
	"testing"
)

// A syntactically valid but fake UUID — real cluster ids are never committed.
const testClusterID = "11111111-2222-4333-8444-555555555555"

// TestResolveExplicitHostVariants covers the range of CAMUNDA_REST_ADDRESS
// forms the Camunda Console produces on copy-paste, all of which must resolve
// to the same region + clusterId + both host families.
func TestResolveExplicitHostVariants(t *testing.T) {
	cases := []struct {
		name string
		host string
	}{
		{"clean api", "https://bru-2.api.camunda.io/" + testClusterID},
		{"clean zeebe", "https://bru-2.zeebe.camunda.io/" + testClusterID},
		{"trailing v2 slash", "https://bru-2.zeebe.camunda.io/" + testClusterID + "/v2/"},
		{"port in authority", "https://bru-2.zeebe.camunda.io:443/" + testClusterID},
		{"stray :443 path segment (Console form)", "https://bru-2.zeebe.camunda.io/:443/" + testClusterID + "/v2/"},
		{"port authority + v2", "https://bru-2.api.camunda.io:443/" + testClusterID + "/v2"},
		{"whitespace around", "  https://bru-2.api.camunda.io/" + testClusterID + "  "},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tgt, err := Resolve(Inputs{ExplicitHost: c.host})
			if err != nil {
				t.Fatalf("Resolve(%q) errored: %v", c.host, err)
			}
			if tgt.Region != "bru-2" {
				t.Errorf("region = %q, want bru-2", tgt.Region)
			}
			if tgt.ClusterID != testClusterID {
				t.Errorf("clusterId = %q, want %q", tgt.ClusterID, testClusterID)
			}
			if tgt.APIHost != "bru-2.api.camunda.io" {
				t.Errorf("apiHost = %q", tgt.APIHost)
			}
			if tgt.ZeebeHost != "bru-2.zeebe.camunda.io" {
				t.Errorf("zeebeHost = %q", tgt.ZeebeHost)
			}
		})
	}
}

func TestResolveRejectsBadHost(t *testing.T) {
	bad := []string{
		"https://example.com/" + testClusterID,    // wrong domain
		"https://bru-2.zeebe.camunda.io/:443/v2/", // no UUID anywhere
		"https://bru-2.api.camunda.io/",           // no clusterId
		"https://bru-2.api.camunda.io/a",          // non-UUID path segment
	}
	for _, h := range bad {
		if _, err := Resolve(Inputs{ExplicitHost: h}); err == nil {
			t.Errorf("Resolve(%q) should have errored, got nil", h)
		}
	}
}

// TestResolveRejectsNonUUIDPathSegment guards the specific case that used to
// slip through as a silent fallback: a non-UUID path segment must be an
// upfront config error, not a clusterId the tool goes on to use. Using it
// anyway built a syntactically valid but nonexistent REST base, and the
// resulting 404 read as "the shared cluster might be paused" -- indistinguishable
// from a real cluster outage.
func TestResolveRejectsNonUUIDPathSegment(t *testing.T) {
	_, err := Resolve(Inputs{ExplicitHost: "http://bru-2.api.camunda.io/a"})
	if err == nil {
		t.Fatal("expected an error for a non-UUID path segment, got nil")
	}
	if !strings.Contains(err.Error(), "invalid cluster id") {
		t.Errorf("error = %q, want it to say \"invalid cluster id\"", err.Error())
	}
}

// TestResolveRejectsNonUUIDClusterIDFlag guards the --cluster-id entry point
// the same way TestResolveRejectsNonUUIDPathSegment guards --host -- both
// must reject a bad clusterId with the same clear error.
func TestResolveRejectsNonUUIDClusterIDFlag(t *testing.T) {
	_, err := Resolve(Inputs{ClusterID: "a", Region: "bru-2"})
	if err == nil {
		t.Fatal("expected an error for a non-UUID --cluster-id, got nil")
	}
	if !strings.Contains(err.Error(), "invalid cluster id") {
		t.Errorf("error = %q, want it to say \"invalid cluster id\"", err.Error())
	}
}

// TestRegionPrecedence confirms an explicit host's region wins over
// CAMUNDA_REGION and a conflict is surfaced as a warning.
func TestRegionPrecedence(t *testing.T) {
	tgt, err := Resolve(Inputs{
		ExplicitHost: "https://bru-2.api.camunda.io/" + testClusterID,
		Region:       "syd-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tgt.Region != "bru-2" {
		t.Errorf("region = %q, want bru-2 (explicit host wins)", tgt.Region)
	}
	if len(tgt.Warnings) == 0 {
		t.Error("expected a warning about the region conflict, got none")
	}
}
