// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsStoragegatewayNfsFileShareInvalidLocationArnRule checks the pattern is valid
type AwsStoragegatewayNfsFileShareInvalidLocationArnRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewAwsStoragegatewayNfsFileShareInvalidLocationArnRule returns new rule with default attributes
func NewAwsStoragegatewayNfsFileShareInvalidLocationArnRule() *AwsStoragegatewayNfsFileShareInvalidLocationArnRule {
	return &AwsStoragegatewayNfsFileShareInvalidLocationArnRule{
		resourceType:  "aws_storagegateway_nfs_file_share",
		attributeName: "location_arn",
		max:           310,
		min:           16,
	}
}

// Name returns the rule name
func (r *AwsStoragegatewayNfsFileShareInvalidLocationArnRule) Name() string {
	return "aws_storagegateway_nfs_file_share_invalid_location_arn"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsStoragegatewayNfsFileShareInvalidLocationArnRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsStoragegatewayNfsFileShareInvalidLocationArnRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsStoragegatewayNfsFileShareInvalidLocationArnRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsStoragegatewayNfsFileShareInvalidLocationArnRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"location_arn must be 310 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"location_arn must be 16 characters or higher",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
