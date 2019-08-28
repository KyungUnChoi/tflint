// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsElasticBeanstalkEnvironmentInvalidDescriptionRule checks the pattern is valid
type AwsElasticBeanstalkEnvironmentInvalidDescriptionRule struct {
	resourceType  string
	attributeName string
	max           int
}

// NewAwsElasticBeanstalkEnvironmentInvalidDescriptionRule returns new rule with default attributes
func NewAwsElasticBeanstalkEnvironmentInvalidDescriptionRule() *AwsElasticBeanstalkEnvironmentInvalidDescriptionRule {
	return &AwsElasticBeanstalkEnvironmentInvalidDescriptionRule{
		resourceType:  "aws_elastic_beanstalk_environment",
		attributeName: "description",
		max:           200,
	}
}

// Name returns the rule name
func (r *AwsElasticBeanstalkEnvironmentInvalidDescriptionRule) Name() string {
	return "aws_elastic_beanstalk_environment_invalid_description"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsElasticBeanstalkEnvironmentInvalidDescriptionRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsElasticBeanstalkEnvironmentInvalidDescriptionRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsElasticBeanstalkEnvironmentInvalidDescriptionRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsElasticBeanstalkEnvironmentInvalidDescriptionRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"description must be 200 characters or less",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
