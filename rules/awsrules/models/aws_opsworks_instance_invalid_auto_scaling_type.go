// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsOpsworksInstanceInvalidAutoScalingTypeRule checks the pattern is valid
type AwsOpsworksInstanceInvalidAutoScalingTypeRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsOpsworksInstanceInvalidAutoScalingTypeRule returns new rule with default attributes
func NewAwsOpsworksInstanceInvalidAutoScalingTypeRule() *AwsOpsworksInstanceInvalidAutoScalingTypeRule {
	return &AwsOpsworksInstanceInvalidAutoScalingTypeRule{
		resourceType:  "aws_opsworks_instance",
		attributeName: "auto_scaling_type",
		enum: []string{
			"load",
			"timer",
		},
	}
}

// Name returns the rule name
func (r *AwsOpsworksInstanceInvalidAutoScalingTypeRule) Name() string {
	return "aws_opsworks_instance_invalid_auto_scaling_type"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsOpsworksInstanceInvalidAutoScalingTypeRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsOpsworksInstanceInvalidAutoScalingTypeRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsOpsworksInstanceInvalidAutoScalingTypeRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsOpsworksInstanceInvalidAutoScalingTypeRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			found := false
			for _, item := range r.enum {
				if item == val {
					found = true
				}
			}
			if !found {
				runner.EmitIssue(
					r,
					`auto_scaling_type is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
