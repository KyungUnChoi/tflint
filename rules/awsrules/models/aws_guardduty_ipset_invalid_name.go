// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsGuarddutyIpsetInvalidNameRule checks the pattern is valid
type AwsGuarddutyIpsetInvalidNameRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewAwsGuarddutyIpsetInvalidNameRule returns new rule with default attributes
func NewAwsGuarddutyIpsetInvalidNameRule() *AwsGuarddutyIpsetInvalidNameRule {
	return &AwsGuarddutyIpsetInvalidNameRule{
		resourceType:  "aws_guardduty_ipset",
		attributeName: "name",
		max:           300,
		min:           1,
	}
}

// Name returns the rule name
func (r *AwsGuarddutyIpsetInvalidNameRule) Name() string {
	return "aws_guardduty_ipset_invalid_name"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsGuarddutyIpsetInvalidNameRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsGuarddutyIpsetInvalidNameRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsGuarddutyIpsetInvalidNameRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsGuarddutyIpsetInvalidNameRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"name must be 300 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"name must be 1 characters or higher",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
