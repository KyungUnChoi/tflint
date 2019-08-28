// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsLambdaFunctionInvalidS3KeyRule checks the pattern is valid
type AwsLambdaFunctionInvalidS3KeyRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewAwsLambdaFunctionInvalidS3KeyRule returns new rule with default attributes
func NewAwsLambdaFunctionInvalidS3KeyRule() *AwsLambdaFunctionInvalidS3KeyRule {
	return &AwsLambdaFunctionInvalidS3KeyRule{
		resourceType:  "aws_lambda_function",
		attributeName: "s3_key",
		max:           1024,
		min:           1,
	}
}

// Name returns the rule name
func (r *AwsLambdaFunctionInvalidS3KeyRule) Name() string {
	return "aws_lambda_function_invalid_s3_key"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsLambdaFunctionInvalidS3KeyRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsLambdaFunctionInvalidS3KeyRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsLambdaFunctionInvalidS3KeyRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsLambdaFunctionInvalidS3KeyRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"s3_key must be 1024 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"s3_key must be 1 characters or higher",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
