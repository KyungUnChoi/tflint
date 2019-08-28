// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"
	"regexp"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsAppsyncDatasourceInvalidNameRule checks the pattern is valid
type AwsAppsyncDatasourceInvalidNameRule struct {
	resourceType  string
	attributeName string
	pattern       *regexp.Regexp
}

// NewAwsAppsyncDatasourceInvalidNameRule returns new rule with default attributes
func NewAwsAppsyncDatasourceInvalidNameRule() *AwsAppsyncDatasourceInvalidNameRule {
	return &AwsAppsyncDatasourceInvalidNameRule{
		resourceType:  "aws_appsync_datasource",
		attributeName: "name",
		pattern:       regexp.MustCompile(`^[_A-Za-z][_0-9A-Za-z]*$`),
	}
}

// Name returns the rule name
func (r *AwsAppsyncDatasourceInvalidNameRule) Name() string {
	return "aws_appsync_datasource_invalid_name"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsAppsyncDatasourceInvalidNameRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsAppsyncDatasourceInvalidNameRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsAppsyncDatasourceInvalidNameRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsAppsyncDatasourceInvalidNameRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if !r.pattern.MatchString(val) {
				runner.EmitIssue(
					r,
					`name does not match valid pattern ^[_A-Za-z][_0-9A-Za-z]*$`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
