// Package grbac implements core of RBAC (role-based access control)
//
// https://en.wikipedia.org/wiki/Role-based_access_control
package grbac

import (
	"errors"
	"sync"
)

//Error codes returned by failures to change roles.
var (
	ErrRoleHasAlreadyPerm   = errors.New("role already has permission")
	ErrRoleNotPerm          = errors.New("role does not have permission")
	ErrRoleHasAlreadyParent = errors.New("role already has the parent ")
	ErrNoParent             = errors.New("parent does not exist")
)

// Roler represents a role in RBAC and describes minimum set of functions
// for storing, managing and checking permissions associated with the role.
type Roler interface {
	Name() string
	Permissions() map[string]bool
	AllPermissions() map[string]bool
	Permit(string) error
	IsAllowed(...string) bool
	Revoke(string) error
	Parents() map[string]Roler
	AllParents() map[string]Roler
	HasParent(string) bool
	SetParent(Roler) error
	RemoveParent(string) error
}

// Role is default implementation of Roler.
type Role struct {
	name        string
	permissions map[string]bool
	parents     map[string]Roler

	mutex sync.RWMutex
}

// NewRole creates a new instance of Role structure.
func NewRole(name string) *Role {
	return &Role{
		name:        name,
		permissions: make(map[string]bool),
		parents:     make(map[string]Roler),
		mutex:       sync.RWMutex{},
	}
}

// Name returns the name of the role.
func (r *Role) Name() string {
	return r.name
}

// Permissions returns a copy of the list of the role permissions,
// but does not include parental permissions.
func (r *Role) Permissions() map[string]bool {
	newPerms := make(map[string]bool)

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for k, v := range r.permissions {
		newPerms[k] = v
	}
	return newPerms
}

// AllPermissions returns a list of all the permissions of the role
// including parental permission.
func (r *Role) AllPermissions() map[string]bool {
	newPerms := make(map[string]bool)

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for k, v := range r.permissions {
		newPerms[k] = v
	}

	for _, p := range r.parents {
		for k, v := range p.AllPermissions() {
			newPerms[k] = v
		}
	}

	return newPerms

}

// Permit adds a permission for to the role.
//
// Returns ErrRoleHasAlreadyPerm if the role already has permission.
func (r *Role) Permit(perm string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.permissions[perm] {
		return ErrRoleHasAlreadyPerm
	}
	r.permissions[perm] = true
	return nil
}

// IsAllowed checks permissions listed in the perms.
// IsAllowed  returns true only if all permissions from perms are present
// in the role.
func (r *Role) IsAllowed(perms ...string) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, perm := range perms {

		if _, ok := r.permissions[perm]; ok {
			continue
		}

		isFound := false
		for _, p := range r.parents {
			if p.IsAllowed(perm) {
				isFound = true
				break
			}
		}

		if !isFound {
			return false
		}
	}

	return true
}

// Revoke revokes permission from the role
// The function returns ErrRoleNotPerm if the role does not have permission
func (r *Role) Revoke(perm string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if !r.permissions[perm] {
		return ErrRoleNotPerm
	}

	delete(r.permissions, perm)
	return nil
}

// Parents returns a map to direct parents of the role.
//
// Key of the map - a name of the parent.
func (r *Role) Parents() map[string]Roler {
	newParents := make(map[string]Roler)

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for k, v := range r.parents {
		newParents[k] = v
	}
	return newParents
}

// AllParents returns a map of direct parents and subpaprents of the role.
//
// Key of the map - a name of the parent.
func (r *Role) AllParents() map[string]Roler {
	newParents := make(map[string]Roler)

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for k, v := range r.parents {
		newParents[k] = v
	}

	for _, p := range r.parents {
		for k, v := range p.AllParents() {
			newParents[k] = v
		}
	}

	return newParents

}

// HasParent checks direct parent in the role
func (r *Role) HasParent(name string) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	_, ok := r.parents[name]
	return ok
}

// SetParent adds to the Role a new parent.
// Returns ErrRoleHasAlreadyParent if a parent is already available.
func (r *Role) SetParent(role Roler) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, ok := r.parents[role.Name()]; ok {
		return ErrRoleHasAlreadyParent
	}

	r.parents[role.Name()] = role
	return nil
}

// RemoveParent remove parent from the role.
func (r *Role) RemoveParent(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, ok := r.parents[name]; !ok {
		return ErrNoParent
	}

	delete(r.parents, name)
	return nil
}
