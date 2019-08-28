// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsGlueCatalogTableInvalidViewOriginalTextRule checks the pattern is valid
type AwsGlueCatalogTableInvalidViewOriginalTextRule struct {
	resourceType  string
	attributeName string
	max           int
}

// NewAwsGlueCatalogTableInvalidViewOriginalTextRule returns new rule with default attributes
func NewAwsGlueCatalogTableInvalidViewOriginalTextRule() *AwsGlueCatalogTableInvalidViewOriginalTextRule {
	return &AwsGlueCatalogTableInvalidViewOriginalTextRule{
		resourceType:  "aws_glue_catalog_table",
		attributeName: "view_original_text",
		max:           409600,
	}
}

// Name returns the rule name
func (r *AwsGlueCatalogTableInvalidViewOriginalTextRule) Name() string {
	return "aws_glue_catalog_table_invalid_view_original_text"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsGlueCatalogTableInvalidViewOriginalTextRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsGlueCatalogTableInvalidViewOriginalTextRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsGlueCatalogTableInvalidViewOriginalTextRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsGlueCatalogTableInvalidViewOriginalTextRule) Check(runner *tflint.Runner) error {
	log.Printf("[INFO] Check `%s` rule for `%s` runner", r.Name(), runner.TFConfigPath())

	return runner.WalkResourceAttributes(r.resourceType, r.attributeName, func(attribute *hcl.Attribute) error {
		var val string
		err := runner.EvaluateExpr(attribute.Expr, &val)

		return runner.EnsureNoError(err, func() error {
			if len(val) > r.max {
				runner.EmitIssue(
					r,
					"view_original_text must be 409600 characters or less",
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
