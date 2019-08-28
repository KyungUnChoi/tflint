// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsS3BucketObjectInvalidStorageClassRule checks the pattern is valid
type AwsS3BucketObjectInvalidStorageClassRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsS3BucketObjectInvalidStorageClassRule returns new rule with default attributes
func NewAwsS3BucketObjectInvalidStorageClassRule() *AwsS3BucketObjectInvalidStorageClassRule {
	return &AwsS3BucketObjectInvalidStorageClassRule{
		resourceType:  "aws_s3_bucket_object",
		attributeName: "storage_class",
		enum: []string{
			"STANDARD",
			"REDUCED_REDUNDANCY",
			"STANDARD_IA",
			"ONEZONE_IA",
			"INTELLIGENT_TIERING",
			"GLACIER",
			"DEEP_ARCHIVE",
		},
	}
}

// Name returns the rule name
func (r *AwsS3BucketObjectInvalidStorageClassRule) Name() string {
	return "aws_s3_bucket_object_invalid_storage_class"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsS3BucketObjectInvalidStorageClassRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsS3BucketObjectInvalidStorageClassRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsS3BucketObjectInvalidStorageClassRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsS3BucketObjectInvalidStorageClassRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			found := false
			for _, item := range r.enum {
				if item == val {
					found = true
				}
			}
			if !found {
				runner.EmitIssue(
					r,
					`storage_class is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
