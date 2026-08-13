// Package hostset resolves the cluster host families and the config-source
// precedence rule: an explicit full host (CAMUNDA_REST_ADDRESS / --host)
// wins over CAMUNDA_REGION (which only substitutes the region slug into the
// default host templates). If both are set and conflict, CAMUNDA_REST_ADDRESS
// wins and a warning names both.
package hostset

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// DefaultRegion is the training default. Always overridable — never
// hardcode a customer's or training group's actual region.
const DefaultRegion = "bru-2"

const OAuthHost = "login.cloud.camunda.io"

// Target is the resolved set of hosts to probe for one run.
type Target struct {
	Region    string
	ClusterID string
	APIHost   string // <region>.api.camunda.io
	ZeebeHost string // <region>.zeebe.camunda.io
	GRPCHost  string // <clusterId>.<region>.zeebe.camunda.io (informational; not actively probed by Layer 1's REST checks)
	OAuthHost string
	Warnings  []string
}

// Inputs mirrors the accepted flags/env vars.
type Inputs struct {
	ExplicitHost string // --host / CAMUNDA_REST_ADDRESS (full URL, may include /<clusterId> path)
	Region       string // --region / CAMUNDA_REGION
	ClusterID    string // --cluster-id / CAMUNDA_CLUSTER_ID
}

// Resolve implements the precedence rule and derives both cluster host
// families. Returns an error only when neither an explicit host nor a
// region+clusterId pair can be resolved (a real config error, exit 4).
func Resolve(in Inputs) (Target, error) {
	t := Target{OAuthHost: OAuthHost}

	if strings.TrimSpace(in.ExplicitHost) != "" {
		region, clusterID, family, err := parseExplicitHost(in.ExplicitHost)
		if err != nil {
			return Target{}, fmt.Errorf("could not parse --host/CAMUNDA_REST_ADDRESS %q: %w", in.ExplicitHost, err)
		}
		t.Region = region
		t.ClusterID = clusterID

		if in.Region != "" && in.Region != region {
			t.Warnings = append(t.Warnings, fmt.Sprintf(
				"CAMUNDA_REGION=%q conflicts with the region in CAMUNDA_REST_ADDRESS (%q) — using %q from CAMUNDA_REST_ADDRESS",
				in.Region, region, region))
		}
		_ = family // the explicit host's own family is always included below via the derived api/zeebe pair
	} else {
		region := DefaultRegion
		if in.Region != "" {
			region = in.Region
		}
		if in.ClusterID == "" {
			return Target{}, fmt.Errorf("no cluster target resolvable: set CAMUNDA_REST_ADDRESS (full URL), or CAMUNDA_CLUSTER_ID plus optionally CAMUNDA_REGION")
		}
		t.Region = region
		t.ClusterID = in.ClusterID
	}

	t.APIHost = fmt.Sprintf("%s.api.camunda.io", t.Region)
	t.ZeebeHost = fmt.Sprintf("%s.zeebe.camunda.io", t.Region)
	t.GRPCHost = fmt.Sprintf("%s.%s.zeebe.camunda.io", t.ClusterID, t.Region)

	return t, nil
}

// RESTBase returns the full REST base URL for a given cluster host family.
func (t Target) RESTBase(host string) string {
	return fmt.Sprintf("https://%s/%s", host, t.ClusterID)
}

// uuidRe matches a Camunda cluster id (a standard UUID). The clusterId is
// always a UUID, which lets us pull it out of a path robustly regardless of
// stray segments.
var uuidRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// parseExplicitHost extracts region, clusterId, and host family from a full
// CAMUNDA_REST_ADDRESS-style URL. It is deliberately tolerant of the exact
// forms the Camunda Console produces on copy-paste, all of which resolve to
// the same cluster:
//
//	https://bru-2.api.camunda.io/<clusterId>
//	https://bru-2.zeebe.camunda.io/<clusterId>/v2/
//	https://bru-2.zeebe.camunda.io:443/<clusterId>
//	https://bru-2.zeebe.camunda.io/:443/<clusterId>/v2/   (Console's odd stray-:443 form)
//
// Strategy: the host gives region+family; the clusterId is the UUID segment
// anywhere in the path (skipping stray ":443", "443", "v2", etc.).
func parseExplicitHost(raw string) (region, clusterID, family string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", "", err
	}
	host := u.Hostname() // strips any :443 port in the authority
	if host == "" {
		return "", "", "", fmt.Errorf("no hostname in URL")
	}

	var domainSuffix string
	switch {
	case strings.HasSuffix(host, ".api.camunda.io"):
		domainSuffix = ".api.camunda.io"
		family = "api"
	case strings.HasSuffix(host, ".zeebe.camunda.io"):
		domainSuffix = ".zeebe.camunda.io"
		family = "zeebe"
	default:
		return "", "", "", fmt.Errorf("host %q is not a recognized <region>.api.camunda.io or <region>.zeebe.camunda.io host", host)
	}
	region = strings.TrimSuffix(host, domainSuffix)
	if region == "" {
		return "", "", "", fmt.Errorf("could not extract region from host %q", host)
	}

	// Find the clusterId: the UUID segment anywhere in the path. This skips
	// stray ":443"/"443" segments, the "/v2/" suffix, and trailing slashes.
	for _, seg := range strings.Split(u.Path, "/") {
		if uuidRe.MatchString(seg) {
			clusterID = seg
			break
		}
	}
	if clusterID == "" {
		// Fall back to the first non-empty, non-port, non-"v2" segment, in
		// case a future clusterId format isn't a UUID — but tell the user
		// what we couldn't find so a genuinely malformed URL is obvious.
		for _, seg := range strings.Split(u.Path, "/") {
			if seg == "" || seg == "v2" || seg == "443" || seg == ":443" {
				continue
			}
			clusterID = seg
			break
		}
	}
	if clusterID == "" {
		return "", "", "", fmt.Errorf("could not find a cluster id (UUID) in the URL path of %q", raw)
	}
	return region, clusterID, family, nil
}
