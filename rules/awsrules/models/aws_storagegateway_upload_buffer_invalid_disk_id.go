// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsStoragegatewayUploadBufferInvalidDiskIDRule checks the pattern is valid
type AwsStoragegatewayUploadBufferInvalidDiskIDRule struct {
	resourceType  string
	attributeName string
	max           int
	min           int
}

// NewAwsStoragegatewayUploadBufferInvalidDiskIDRule returns new rule with default attributes
func NewAwsStoragegatewayUploadBufferInvalidDiskIDRule() *AwsStoragegatewayUploadBufferInvalidDiskIDRule {
	return &AwsStoragegatewayUploadBufferInvalidDiskIDRule{
		resourceType:  "aws_storagegateway_upload_buffer",
		attributeName: "disk_id",
		max:           300,
		min:           1,
	}
}

// Name returns the rule name
func (r *AwsStoragegatewayUploadBufferInvalidDiskIDRule) Name() string {
	return "aws_storagegateway_upload_buffer_invalid_disk_id"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsStoragegatewayUploadBufferInvalidDiskIDRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsStoragegatewayUploadBufferInvalidDiskIDRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsStoragegatewayUploadBufferInvalidDiskIDRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsStoragegatewayUploadBufferInvalidDiskIDRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"disk_id must be 300 characters or less",
					attribute.Expr.Range(),
				)
			}
			if len(val) < r.min {
				runner.EmitIssue(
					r,
					"disk_id must be 1 characters or higher",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
