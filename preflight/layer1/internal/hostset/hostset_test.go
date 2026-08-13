package hostset

import "testing"

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
	}
	for _, h := range bad {
		if _, err := Resolve(Inputs{ExplicitHost: h}); err == nil {
			t.Errorf("Resolve(%q) should have errored, got nil", h)
		}
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
