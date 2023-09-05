// Package schema describes the definition of one entity type in the graph, like User or Group.
// # This manifest was generated by ymir. DO NOT EDIT.
package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"

	"github.com/kubuskotak/king/pkg/version"
)

// Ymir holds the schema definition for the Ymir entity.
type Ymir struct {
	ent.Schema
}

// Fields of the Ymir.
func (Ymir) Fields() []ent.Field {
	return []ent.Field{
		field.String("version").Default(version.GetVersion().VersionNumber()),
	}
}

// Edges of the Ymir.
func (Ymir) Edges() []ent.Edge {
	return nil
}
