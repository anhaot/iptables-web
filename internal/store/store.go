package store

import "iptables-web/internal/model"

// Store is the persistence interface for iptables rules.
type Store interface {
	List(chain string) ([]*model.Rule, error)
	ListByBackend(backend, chain string) ([]*model.Rule, error)
	ListByTarget(backend, chain string) ([]*model.Rule, error)
	Get(id string) (*model.Rule, error)
	Create(rule *model.Rule) error
	Update(rule *model.Rule) error
	Delete(id string) (*model.Rule, error)
	Toggle(id string) (*model.Rule, error)
	Reorder(chain string, ids []string) error
	ReorderByBackend(backend, chain string, ids []string) error
	ReorderByTarget(backend, chain string, ids []string) error
	ReplaceAll(rules []*model.Rule) error
	All() ([]*model.Rule, error)
	Save() error
	Load() error
}
