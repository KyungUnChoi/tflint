// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsOrganizationsPolicyInvalidDescriptionRule checks the pattern is valid
type AwsOrganizationsPolicyInvalidDescriptionRule struct {
	resourceType  string
	attributeName string
	max           int
}

// NewAwsOrganizationsPolicyInvalidDescriptionRule returns new rule with default attributes
func NewAwsOrganizationsPolicyInvalidDescriptionRule() *AwsOrganizationsPolicyInvalidDescriptionRule {
	return &AwsOrganizationsPolicyInvalidDescriptionRule{
		resourceType:  "aws_organizations_policy",
		attributeName: "description",
		max:           512,
	}
}

// Name returns the rule name
func (r *AwsOrganizationsPolicyInvalidDescriptionRule) Name() string {
	return "aws_organizations_policy_invalid_description"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsOrganizationsPolicyInvalidDescriptionRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsOrganizationsPolicyInvalidDescriptionRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsOrganizationsPolicyInvalidDescriptionRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsOrganizationsPolicyInvalidDescriptionRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"description must be 512 characters or less",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
