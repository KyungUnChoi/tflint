package gcprules

import (
	"fmt"
	"strings"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint/tflint"
)

// GkeHardenWorkloadIdentityRule checks whether ...
type GkeHardenWorkloadIdentityRule struct {
	resourceType  string
	blockName     string
	attributeName string
	validSuffix   string
}

// NewGkeHardenWorkloadIdentityRule returns a new rule
func NewGkeHardenWorkloadIdentityRule() *GkeHardenWorkloadIdentityRule {
	return &GkeHardenWorkloadIdentityRule{
		resourceType:  "google_container_cluster",
		blockName:     "workload_identity_config",
		attributeName: "identity_namespace",
		validSuffix:   ".svc.id.goog",
	}
}

// Name returns the rule name
func (r *GkeHardenWorkloadIdentityRule) Name() string {
	return "gke_harden_workload_identity"
}

// Enabled returns whether the rule is enabled by default
func (r *GkeHardenWorkloadIdentityRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *GkeHardenWorkloadIdentityRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *GkeHardenWorkloadIdentityRule) Link() string {
	return ""
}

// Check checks whether valid machine type is configured
func (r *GkeHardenWorkloadIdentityRule) Check(runner *tflint.Runner) (err error) {
	var givenValue string

	return runner.WalkResourceBlocks(r.resourceType, r.blockName,
		func(block *hcl.Block) error {
			var attributes, _ = block.Body.JustAttributes()
			var attribute = attributes[r.attributeName]
			err := runner.EvaluateExpr(attribute.Expr, &givenValue)
			return r.ensureNoError(err, givenValue, r.attributeName, attribute, runner)
		},
	)
}

func (r *GkeHardenWorkloadIdentityRule) ensureNoError(err error, value, name string, attr *hcl.Attribute, runner *tflint.Runner) error {
	return runner.EnsureNoError(err, func() error {
		found := false
		if strings.HasSuffix(value, r.validSuffix) {
			found = true
		}
		if !found {
			runner.EmitIssue(
				r,
				fmt.Sprintf(`GKE harden: %s should have a suffix .svc.id.goog like [project_id].svc.id.goog for better security.`, name),
				attr.Expr.Range(),
			)
		}
		return nil
	})
}
