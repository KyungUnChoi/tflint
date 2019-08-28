// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"
	"regexp"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsCloudwatchMetricAlarmInvalidNamespaceRule checks the pattern is valid
type AwsCloudwatchMetricAlarmInvalidNamespaceRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
	pattern       *regexp.Regexp
}

// NewAwsCloudwatchMetricAlarmInvalidNamespaceRule returns new rule with default attributes
func NewAwsCloudwatchMetricAlarmInvalidNamespaceRule() *AwsCloudwatchMetricAlarmInvalidNamespaceRule {
	return &AwsCloudwatchMetricAlarmInvalidNamespaceRule{
		resourceType:  "aws_cloudwatch_metric_alarm",
		attributeName: "namespace",
		max:           255,
		min:           1,
		pattern:       regexp.MustCompile(`^[^:].*$`),
	}
}

// Name returns the rule name
func (r *AwsCloudwatchMetricAlarmInvalidNamespaceRule) Name() string {
	return "aws_cloudwatch_metric_alarm_invalid_namespace"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsCloudwatchMetricAlarmInvalidNamespaceRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsCloudwatchMetricAlarmInvalidNamespaceRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsCloudwatchMetricAlarmInvalidNamespaceRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsCloudwatchMetricAlarmInvalidNamespaceRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"namespace must be 255 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"namespace must be 1 characters or higher",
					attribute.Expr.Range(),
				)
			}
			if !r.pattern.MatchString(val) {
				runner.EmitIssue(
					r,
					`namespace does not match valid pattern ^[^:].*$`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
