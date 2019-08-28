// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsRoute53HealthCheckInvalidFqdnRule checks the pattern is valid
type AwsRoute53HealthCheckInvalidFqdnRule struct {
	resourceType  string
	attributeName string
	max           int
}

// NewAwsRoute53HealthCheckInvalidFqdnRule returns new rule with default attributes
func NewAwsRoute53HealthCheckInvalidFqdnRule() *AwsRoute53HealthCheckInvalidFqdnRule {
	return &AwsRoute53HealthCheckInvalidFqdnRule{
		resourceType:  "aws_route53_health_check",
		attributeName: "fqdn",
		max:           255,
	}
}

// Name returns the rule name
func (r *AwsRoute53HealthCheckInvalidFqdnRule) Name() string {
	return "aws_route53_health_check_invalid_fqdn"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsRoute53HealthCheckInvalidFqdnRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsRoute53HealthCheckInvalidFqdnRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsRoute53HealthCheckInvalidFqdnRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsRoute53HealthCheckInvalidFqdnRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"fqdn must be 255 characters or less",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
