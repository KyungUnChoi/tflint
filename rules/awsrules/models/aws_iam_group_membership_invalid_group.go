// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"
	"regexp"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsIAMGroupMembershipInvalidGroupRule checks the pattern is valid
type AwsIAMGroupMembershipInvalidGroupRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
	pattern       *regexp.Regexp
}

// NewAwsIAMGroupMembershipInvalidGroupRule returns new rule with default attributes
func NewAwsIAMGroupMembershipInvalidGroupRule() *AwsIAMGroupMembershipInvalidGroupRule {
	return &AwsIAMGroupMembershipInvalidGroupRule{
		resourceType:  "aws_iam_group_membership",
		attributeName: "group",
		max:           128,
		min:           1,
		pattern:       regexp.MustCompile(`^[\w+=,.@-]+$`),
	}
}

// Name returns the rule name
func (r *AwsIAMGroupMembershipInvalidGroupRule) Name() string {
	return "aws_iam_group_membership_invalid_group"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsIAMGroupMembershipInvalidGroupRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsIAMGroupMembershipInvalidGroupRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsIAMGroupMembershipInvalidGroupRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsIAMGroupMembershipInvalidGroupRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"group must be 128 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"group must be 1 characters or higher",
					attribute.Expr.Range(),
				)
			}
			if !r.pattern.MatchString(val) {
				runner.EmitIssue(
					r,
					`group does not match valid pattern ^[\w+=,.@-]+$`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
