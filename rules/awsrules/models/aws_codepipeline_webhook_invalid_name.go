// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"
	"regexp"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsCodepipelineWebhookInvalidNameRule checks the pattern is valid
type AwsCodepipelineWebhookInvalidNameRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
	pattern       *regexp.Regexp
}

// NewAwsCodepipelineWebhookInvalidNameRule returns new rule with default attributes
func NewAwsCodepipelineWebhookInvalidNameRule() *AwsCodepipelineWebhookInvalidNameRule {
	return &AwsCodepipelineWebhookInvalidNameRule{
		resourceType:  "aws_codepipeline_webhook",
		attributeName: "name",
		max:           100,
		min:           1,
		pattern:       regexp.MustCompile(`^[A-Za-z0-9.@\-_]+$`),
	}
}

// Name returns the rule name
func (r *AwsCodepipelineWebhookInvalidNameRule) Name() string {
	return "aws_codepipeline_webhook_invalid_name"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsCodepipelineWebhookInvalidNameRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsCodepipelineWebhookInvalidNameRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsCodepipelineWebhookInvalidNameRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsCodepipelineWebhookInvalidNameRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"name must be 100 characters or less",
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
			if !r.pattern.MatchString(val) {
				runner.EmitIssue(
					r,
					`name does not match valid pattern ^[A-Za-z0-9.@\-_]+$`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
