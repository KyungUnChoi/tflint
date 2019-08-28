// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsIAMGroupPolicyAttachmentInvalidPolicyArnRule checks the pattern is valid
type AwsIAMGroupPolicyAttachmentInvalidPolicyArnRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewAwsIAMGroupPolicyAttachmentInvalidPolicyArnRule returns new rule with default attributes
func NewAwsIAMGroupPolicyAttachmentInvalidPolicyArnRule() *AwsIAMGroupPolicyAttachmentInvalidPolicyArnRule {
	return &AwsIAMGroupPolicyAttachmentInvalidPolicyArnRule{
		resourceType:  "aws_iam_group_policy_attachment",
		attributeName: "policy_arn",
		max:           2048,
		min:           20,
	}
}

// Name returns the rule name
func (r *AwsIAMGroupPolicyAttachmentInvalidPolicyArnRule) Name() string {
	return "aws_iam_group_policy_attachment_invalid_policy_arn"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsIAMGroupPolicyAttachmentInvalidPolicyArnRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsIAMGroupPolicyAttachmentInvalidPolicyArnRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsIAMGroupPolicyAttachmentInvalidPolicyArnRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsIAMGroupPolicyAttachmentInvalidPolicyArnRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"policy_arn must be 2048 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"policy_arn must be 20 characters or higher",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
