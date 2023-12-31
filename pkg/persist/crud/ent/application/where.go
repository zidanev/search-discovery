// Code generated by ent, DO NOT EDIT.

package application

import (
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"github.com/kubuskotak/king/pkg/persist/crud/ent/predicate"
)

// ID filters vertices based on their ID field.
func ID(id string) predicate.Application {
	return predicate.Application(sql.FieldEQ(FieldID, id))
}

// IDEQ applies the EQ predicate on the ID field.
func IDEQ(id string) predicate.Application {
	return predicate.Application(sql.FieldEQ(FieldID, id))
}

// IDNEQ applies the NEQ predicate on the ID field.
func IDNEQ(id string) predicate.Application {
	return predicate.Application(sql.FieldNEQ(FieldID, id))
}

// IDIn applies the In predicate on the ID field.
func IDIn(ids ...string) predicate.Application {
	return predicate.Application(sql.FieldIn(FieldID, ids...))
}

// IDNotIn applies the NotIn predicate on the ID field.
func IDNotIn(ids ...string) predicate.Application {
	return predicate.Application(sql.FieldNotIn(FieldID, ids...))
}

// IDGT applies the GT predicate on the ID field.
func IDGT(id string) predicate.Application {
	return predicate.Application(sql.FieldGT(FieldID, id))
}

// IDGTE applies the GTE predicate on the ID field.
func IDGTE(id string) predicate.Application {
	return predicate.Application(sql.FieldGTE(FieldID, id))
}

// IDLT applies the LT predicate on the ID field.
func IDLT(id string) predicate.Application {
	return predicate.Application(sql.FieldLT(FieldID, id))
}

// IDLTE applies the LTE predicate on the ID field.
func IDLTE(id string) predicate.Application {
	return predicate.Application(sql.FieldLTE(FieldID, id))
}

// IDEqualFold applies the EqualFold predicate on the ID field.
func IDEqualFold(id string) predicate.Application {
	return predicate.Application(sql.FieldEqualFold(FieldID, id))
}

// IDContainsFold applies the ContainsFold predicate on the ID field.
func IDContainsFold(id string) predicate.Application {
	return predicate.Application(sql.FieldContainsFold(FieldID, id))
}

// Name applies equality check predicate on the "name" field. It's identical to NameEQ.
func Name(v string) predicate.Application {
	return predicate.Application(sql.FieldEQ(FieldName, v))
}

// Apikey applies equality check predicate on the "apikey" field. It's identical to ApikeyEQ.
func Apikey(v string) predicate.Application {
	return predicate.Application(sql.FieldEQ(FieldApikey, v))
}

// NameEQ applies the EQ predicate on the "name" field.
func NameEQ(v string) predicate.Application {
	return predicate.Application(sql.FieldEQ(FieldName, v))
}

// NameNEQ applies the NEQ predicate on the "name" field.
func NameNEQ(v string) predicate.Application {
	return predicate.Application(sql.FieldNEQ(FieldName, v))
}

// NameIn applies the In predicate on the "name" field.
func NameIn(vs ...string) predicate.Application {
	return predicate.Application(sql.FieldIn(FieldName, vs...))
}

// NameNotIn applies the NotIn predicate on the "name" field.
func NameNotIn(vs ...string) predicate.Application {
	return predicate.Application(sql.FieldNotIn(FieldName, vs...))
}

// NameGT applies the GT predicate on the "name" field.
func NameGT(v string) predicate.Application {
	return predicate.Application(sql.FieldGT(FieldName, v))
}

// NameGTE applies the GTE predicate on the "name" field.
func NameGTE(v string) predicate.Application {
	return predicate.Application(sql.FieldGTE(FieldName, v))
}

// NameLT applies the LT predicate on the "name" field.
func NameLT(v string) predicate.Application {
	return predicate.Application(sql.FieldLT(FieldName, v))
}

// NameLTE applies the LTE predicate on the "name" field.
func NameLTE(v string) predicate.Application {
	return predicate.Application(sql.FieldLTE(FieldName, v))
}

// NameContains applies the Contains predicate on the "name" field.
func NameContains(v string) predicate.Application {
	return predicate.Application(sql.FieldContains(FieldName, v))
}

// NameHasPrefix applies the HasPrefix predicate on the "name" field.
func NameHasPrefix(v string) predicate.Application {
	return predicate.Application(sql.FieldHasPrefix(FieldName, v))
}

// NameHasSuffix applies the HasSuffix predicate on the "name" field.
func NameHasSuffix(v string) predicate.Application {
	return predicate.Application(sql.FieldHasSuffix(FieldName, v))
}

// NameEqualFold applies the EqualFold predicate on the "name" field.
func NameEqualFold(v string) predicate.Application {
	return predicate.Application(sql.FieldEqualFold(FieldName, v))
}

// NameContainsFold applies the ContainsFold predicate on the "name" field.
func NameContainsFold(v string) predicate.Application {
	return predicate.Application(sql.FieldContainsFold(FieldName, v))
}

// ApikeyEQ applies the EQ predicate on the "apikey" field.
func ApikeyEQ(v string) predicate.Application {
	return predicate.Application(sql.FieldEQ(FieldApikey, v))
}

// ApikeyNEQ applies the NEQ predicate on the "apikey" field.
func ApikeyNEQ(v string) predicate.Application {
	return predicate.Application(sql.FieldNEQ(FieldApikey, v))
}

// ApikeyIn applies the In predicate on the "apikey" field.
func ApikeyIn(vs ...string) predicate.Application {
	return predicate.Application(sql.FieldIn(FieldApikey, vs...))
}

// ApikeyNotIn applies the NotIn predicate on the "apikey" field.
func ApikeyNotIn(vs ...string) predicate.Application {
	return predicate.Application(sql.FieldNotIn(FieldApikey, vs...))
}

// ApikeyGT applies the GT predicate on the "apikey" field.
func ApikeyGT(v string) predicate.Application {
	return predicate.Application(sql.FieldGT(FieldApikey, v))
}

// ApikeyGTE applies the GTE predicate on the "apikey" field.
func ApikeyGTE(v string) predicate.Application {
	return predicate.Application(sql.FieldGTE(FieldApikey, v))
}

// ApikeyLT applies the LT predicate on the "apikey" field.
func ApikeyLT(v string) predicate.Application {
	return predicate.Application(sql.FieldLT(FieldApikey, v))
}

// ApikeyLTE applies the LTE predicate on the "apikey" field.
func ApikeyLTE(v string) predicate.Application {
	return predicate.Application(sql.FieldLTE(FieldApikey, v))
}

// ApikeyContains applies the Contains predicate on the "apikey" field.
func ApikeyContains(v string) predicate.Application {
	return predicate.Application(sql.FieldContains(FieldApikey, v))
}

// ApikeyHasPrefix applies the HasPrefix predicate on the "apikey" field.
func ApikeyHasPrefix(v string) predicate.Application {
	return predicate.Application(sql.FieldHasPrefix(FieldApikey, v))
}

// ApikeyHasSuffix applies the HasSuffix predicate on the "apikey" field.
func ApikeyHasSuffix(v string) predicate.Application {
	return predicate.Application(sql.FieldHasSuffix(FieldApikey, v))
}

// ApikeyEqualFold applies the EqualFold predicate on the "apikey" field.
func ApikeyEqualFold(v string) predicate.Application {
	return predicate.Application(sql.FieldEqualFold(FieldApikey, v))
}

// ApikeyContainsFold applies the ContainsFold predicate on the "apikey" field.
func ApikeyContainsFold(v string) predicate.Application {
	return predicate.Application(sql.FieldContainsFold(FieldApikey, v))
}

// HasUser applies the HasEdge predicate on the "user" edge.
func HasUser() predicate.Application {
	return predicate.Application(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.M2O, true, UserTable, UserColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasUserWith applies the HasEdge predicate on the "user" edge with a given conditions (other predicates).
func HasUserWith(preds ...predicate.User) predicate.Application {
	return predicate.Application(func(s *sql.Selector) {
		step := newUserStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// HasIndexes applies the HasEdge predicate on the "indexes" edge.
func HasIndexes() predicate.Application {
	return predicate.Application(func(s *sql.Selector) {
		step := sqlgraph.NewStep(
			sqlgraph.From(Table, FieldID),
			sqlgraph.Edge(sqlgraph.O2M, false, IndexesTable, IndexesColumn),
		)
		sqlgraph.HasNeighbors(s, step)
	})
}

// HasIndexesWith applies the HasEdge predicate on the "indexes" edge with a given conditions (other predicates).
func HasIndexesWith(preds ...predicate.Index) predicate.Application {
	return predicate.Application(func(s *sql.Selector) {
		step := newIndexesStep()
		sqlgraph.HasNeighborsWith(s, step, func(s *sql.Selector) {
			for _, p := range preds {
				p(s)
			}
		})
	})
}

// And groups predicates with the AND operator between them.
func And(predicates ...predicate.Application) predicate.Application {
	return predicate.Application(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for _, p := range predicates {
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Or groups predicates with the OR operator between them.
func Or(predicates ...predicate.Application) predicate.Application {
	return predicate.Application(func(s *sql.Selector) {
		s1 := s.Clone().SetP(nil)
		for i, p := range predicates {
			if i > 0 {
				s1.Or()
			}
			p(s1)
		}
		s.Where(s1.P())
	})
}

// Not applies the not operator on the given predicate.
func Not(p predicate.Application) predicate.Application {
	return predicate.Application(func(s *sql.Selector) {
		p(s.Not())
	})
}
