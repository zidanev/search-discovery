// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/application"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/index"
)

// IndexCreate is the builder for creating a Index entity.
type IndexCreate struct {
	config
	mutation *IndexMutation
	hooks    []Hook
}

// SetName sets the "name" field.
func (ic *IndexCreate) SetName(s string) *IndexCreate {
	ic.mutation.SetName(s)
	return ic
}

// SetApplicationID sets the "application" edge to the Application entity by ID.
func (ic *IndexCreate) SetApplicationID(id string) *IndexCreate {
	ic.mutation.SetApplicationID(id)
	return ic
}

// SetNillableApplicationID sets the "application" edge to the Application entity by ID if the given value is not nil.
func (ic *IndexCreate) SetNillableApplicationID(id *string) *IndexCreate {
	if id != nil {
		ic = ic.SetApplicationID(*id)
	}
	return ic
}

// SetApplication sets the "application" edge to the Application entity.
func (ic *IndexCreate) SetApplication(a *Application) *IndexCreate {
	return ic.SetApplicationID(a.ID)
}

// Mutation returns the IndexMutation object of the builder.
func (ic *IndexCreate) Mutation() *IndexMutation {
	return ic.mutation
}

// Save creates the Index in the database.
func (ic *IndexCreate) Save(ctx context.Context) (*Index, error) {
	return withHooks(ctx, ic.sqlSave, ic.mutation, ic.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (ic *IndexCreate) SaveX(ctx context.Context) *Index {
	v, err := ic.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ic *IndexCreate) Exec(ctx context.Context) error {
	_, err := ic.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ic *IndexCreate) ExecX(ctx context.Context) {
	if err := ic.Exec(ctx); err != nil {
		panic(err)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ic *IndexCreate) check() error {
	if _, ok := ic.mutation.Name(); !ok {
		return &ValidationError{Name: "name", err: errors.New(`ent: missing required field "Index.name"`)}
	}
	return nil
}

func (ic *IndexCreate) sqlSave(ctx context.Context) (*Index, error) {
	if err := ic.check(); err != nil {
		return nil, err
	}
	_node, _spec := ic.createSpec()
	if err := sqlgraph.CreateNode(ctx, ic.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	ic.mutation.id = &_node.ID
	ic.mutation.done = true
	return _node, nil
}

func (ic *IndexCreate) createSpec() (*Index, *sqlgraph.CreateSpec) {
	var (
		_node = &Index{config: ic.config}
		_spec = sqlgraph.NewCreateSpec(index.Table, sqlgraph.NewFieldSpec(index.FieldID, field.TypeInt))
	)
	if value, ok := ic.mutation.Name(); ok {
		_spec.SetField(index.FieldName, field.TypeString, value)
		_node.Name = value
	}
	if nodes := ic.mutation.ApplicationIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   index.ApplicationTable,
			Columns: []string{index.ApplicationColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(application.FieldID, field.TypeString),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.application_indexes = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// IndexCreateBulk is the builder for creating many Index entities in bulk.
type IndexCreateBulk struct {
	config
	builders []*IndexCreate
}

// Save creates the Index entities in the database.
func (icb *IndexCreateBulk) Save(ctx context.Context) ([]*Index, error) {
	specs := make([]*sqlgraph.CreateSpec, len(icb.builders))
	nodes := make([]*Index, len(icb.builders))
	mutators := make([]Mutator, len(icb.builders))
	for i := range icb.builders {
		func(i int, root context.Context) {
			builder := icb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*IndexMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, icb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, icb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, icb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (icb *IndexCreateBulk) SaveX(ctx context.Context) []*Index {
	v, err := icb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (icb *IndexCreateBulk) Exec(ctx context.Context) error {
	_, err := icb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (icb *IndexCreateBulk) ExecX(ctx context.Context) {
	if err := icb.Exec(ctx); err != nil {
		panic(err)
	}
}