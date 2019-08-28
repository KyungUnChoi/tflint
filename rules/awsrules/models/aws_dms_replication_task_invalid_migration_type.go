// This file generated by `tools/model-rule-gen/main.go`. DO NOT EDIT

package models

import (
	"log"

	"github.com/hashicorp/hcl2/hcl"
	"github.com/wata727/tflint/tflint"
)

// AwsDmsReplicationTaskInvalidMigrationTypeRule checks the pattern is valid
type AwsDmsReplicationTaskInvalidMigrationTypeRule struct {
	resourceType  string
	attributeName string
	enum          []string
}

// NewAwsDmsReplicationTaskInvalidMigrationTypeRule returns new rule with default attributes
func NewAwsDmsReplicationTaskInvalidMigrationTypeRule() *AwsDmsReplicationTaskInvalidMigrationTypeRule {
	return &AwsDmsReplicationTaskInvalidMigrationTypeRule{
		resourceType:  "aws_dms_replication_task",
		attributeName: "migration_type",
		enum: []string{
			"full-load",
			"cdc",
			"full-load-and-cdc",
		},
	}
}

// Name returns the rule name
func (r *AwsDmsReplicationTaskInvalidMigrationTypeRule) Name() string {
	return "aws_dms_replication_task_invalid_migration_type"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsDmsReplicationTaskInvalidMigrationTypeRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsDmsReplicationTaskInvalidMigrationTypeRule) Severity() string {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsDmsReplicationTaskInvalidMigrationTypeRule) Link() string {
	return ""
}

// Check checks the pattern is valid
func (r *AwsDmsReplicationTaskInvalidMigrationTypeRule) Check(runner *tflint.Runner) error {
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
					`migration_type is not a valid value`,
					attribute.Expr.Range(),
				)
			}
			return nil
		})
	})
}
