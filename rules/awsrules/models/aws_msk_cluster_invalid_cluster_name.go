// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/issue"
	"github.com/wata727/tflint/tflint"
)

// AwsMskClusterInvalidClusterNameRule checks the pattern is valid
type AwsMskClusterInvalidClusterNameRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewAwsMskClusterInvalidClusterNameRule returns new rule with default attributes
func NewAwsMskClusterInvalidClusterNameRule() *AwsMskClusterInvalidClusterNameRule {
	return &AwsMskClusterInvalidClusterNameRule{
		resourceType:  "aws_msk_cluster",
		attributeName: "cluster_name",
		max:           64,
		min:           1,
	}
}

// Name returns the rule name
func (r *AwsMskClusterInvalidClusterNameRule) Name() string {
	return "aws_msk_cluster_invalid_cluster_name"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsMskClusterInvalidClusterNameRule) Enabled() bool {
	return true
}

// Type returns the rule severity
func (r *AwsMskClusterInvalidClusterNameRule) Type() string {
	return issue.ERROR
}

// Link returns the rule reference link
func (r *AwsMskClusterInvalidClusterNameRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsMskClusterInvalidClusterNameRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"cluster_name must be 64 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"cluster_name must be 1 characters or higher",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}