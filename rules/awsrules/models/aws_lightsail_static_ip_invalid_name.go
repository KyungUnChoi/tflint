// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"
	"regexp"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsLightsailStaticIPInvalidNameRule checks the pattern is valid
type AwsLightsailStaticIPInvalidNameRule struct {
	resourceType  string
	attributeName string
	pattern       *regexp.Regexp
}

// NewAwsLightsailStaticIPInvalidNameRule returns new rule with default attributes
func NewAwsLightsailStaticIPInvalidNameRule() *AwsLightsailStaticIPInvalidNameRule {
	return &AwsLightsailStaticIPInvalidNameRule{
		resourceType:  "aws_lightsail_static_ip",
		attributeName: "name",
		pattern:       regexp.MustCompile(`^\w[\w\-]*\w$`),
	}
}

// Name returns the rule name
func (r *AwsLightsailStaticIPInvalidNameRule) Name() string {
	return "aws_lightsail_static_ip_invalid_name"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsLightsailStaticIPInvalidNameRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsLightsailStaticIPInvalidNameRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsLightsailStaticIPInvalidNameRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsLightsailStaticIPInvalidNameRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if !r.pattern.MatchString(val) {
				runner.EmitIssue(
					r,
					`name does not match valid pattern ^\w[\w\-]*\w$`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
