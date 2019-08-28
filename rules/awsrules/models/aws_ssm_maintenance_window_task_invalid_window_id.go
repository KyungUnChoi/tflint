// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"
	"regexp"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsSsmMaintenanceWindowTaskInvalidWindowIDRule checks the pattern is valid
type AwsSsmMaintenanceWindowTaskInvalidWindowIDRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
	pattern       *regexp.Regexp
}

// NewAwsSsmMaintenanceWindowTaskInvalidWindowIDRule returns new rule with default attributes
func NewAwsSsmMaintenanceWindowTaskInvalidWindowIDRule() *AwsSsmMaintenanceWindowTaskInvalidWindowIDRule {
	return &AwsSsmMaintenanceWindowTaskInvalidWindowIDRule{
		resourceType:  "aws_ssm_maintenance_window_task",
		attributeName: "window_id",
		max:           20,
		min:           20,
		pattern:       regexp.MustCompile(`^mw-[0-9a-f]{17}$`),
	}
}

// Name returns the rule name
func (r *AwsSsmMaintenanceWindowTaskInvalidWindowIDRule) Name() string {
	return "aws_ssm_maintenance_window_task_invalid_window_id"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsSsmMaintenanceWindowTaskInvalidWindowIDRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsSsmMaintenanceWindowTaskInvalidWindowIDRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsSsmMaintenanceWindowTaskInvalidWindowIDRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsSsmMaintenanceWindowTaskInvalidWindowIDRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"window_id must be 20 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"window_id must be 20 characters or higher",
					attribute.Expr.Range(),
				)
			}
			if !r.pattern.MatchString(val) {
				runner.EmitIssue(
					r,
					`window_id does not match valid pattern ^mw-[0-9a-f]{17}$`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
