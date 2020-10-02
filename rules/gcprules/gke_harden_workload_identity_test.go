package gcprules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint/tflint"
)

func Test_GkeHardenWorkloadIdentityRule(t *testing.T) {
	tfContent := `
		    resource "google_container_cluster" "private" {	
			  name             = "my-cluster"
			  workload_identity_config {
                identity_namespace = "someprojectid.svc.id.goog.err"
  			  }
            }`

	cases := []struct {
		Name     string
		Content  string
		Expected tflint.Issues
	}{
		{
			Name:    "issue found",
			Content: tfContent,
			Expected: tflint.Issues{
				{
					Rule:    NewGkeHardenWorkloadIdentityRule(),
					Message: "GKE harden: identity_namespace should have a suffix .svc.id.goog like [project_id].svc.id.goog for better security.",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 5, Column: 38},
						End:      hcl.Pos{Line: 5, Column: 69},
					},
				},
			},
		},
	}

	rule := NewGkeHardenWorkloadIdentityRule()

	for _, tc := range cases {
		runner := tflint.TestRunner(t, map[string]string{"resource.tf": tc.Content})

		if err := rule.Check(runner); err != nil {
			t.Fatalf("Unexpected error occurred: %s", err)
		}

		tflint.AssertIssues(t, tc.Expected, runner.Issues)
	}
}
