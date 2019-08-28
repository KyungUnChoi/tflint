// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsSsmDocumentInvalidDocumentFormatRule checks the pattern is valid
type AwsSsmDocumentInvalidDocumentFormatRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsSsmDocumentInvalidDocumentFormatRule returns new rule with default attributes
func NewAwsSsmDocumentInvalidDocumentFormatRule() *AwsSsmDocumentInvalidDocumentFormatRule {
	return &AwsSsmDocumentInvalidDocumentFormatRule{
		resourceType:  "aws_ssm_document",
		attributeName: "document_format",
		enum: []string{
			"YAML",
			"JSON",
		},
	}
}

// Name returns the rule name
func (r *AwsSsmDocumentInvalidDocumentFormatRule) Name() string {
	return "aws_ssm_document_invalid_document_format"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsSsmDocumentInvalidDocumentFormatRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsSsmDocumentInvalidDocumentFormatRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsSsmDocumentInvalidDocumentFormatRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsSsmDocumentInvalidDocumentFormatRule) Check(runner *tflint.Runner) error {
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
					`document_format is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
