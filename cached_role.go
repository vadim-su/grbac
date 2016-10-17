package grbac

import (
	"errors"
	"sync"
)

var (
	ErrRoleHasChild  = errors.New("role already has child")
	ErrNoChild       = errors.New("child does not exist")
	ErrNoCachedRoler = errors.New("parent is not CachedRoler!")
)

type CachedRoler interface {
	Roler
	Children() map[string]CachedRoler
	SetChild(CachedRoler) error
	RemoveChild(string) error
	UpdateCache()
}

type CachedRole struct {
	*Role
	children   map[string]CachedRoler
	permsCache map[string]bool

	mutex sync.RWMutex
}

func NewCachedRole(name string) *CachedRole {
	return &CachedRole{
		Role:       NewRole(name),
		children:   make(map[string]CachedRoler),
		permsCache: make(map[string]bool),
	}
}

func (r *CachedRole) Children() map[string]CachedRoler {
	newChildren := make(map[string]CachedRoler)

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for name, child := range r.children {
		newChildren[name] = child
	}

	return newChildren
}

func (r *CachedRole) SetChild(child CachedRoler) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, ok := r.children[child.Name()]; ok {
		return ErrRoleHasChild
	}

	r.children[child.Name()] = child
	return nil
}

func (r *CachedRole) RemoveChild(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, ok := r.children[name]; !ok {
		return ErrNoChild
	}

	delete(r.children, name)

	return nil
}

func (r *CachedRole) UpdateCache() {
	perms := r.Role.AllPermissions()

	r.mutex.Lock()
	r.permsCache = perms
	r.mutex.Unlock()

	for _, child := range r.Children() {
		child.UpdateCache()
	}
}

func (r *CachedRole) AllPermissions() map[string]bool {
	newPerms := make(map[string]bool)

	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for p := range r.permsCache {
		newPerms[p] = true
	}

	return newPerms
}

func (r *CachedRole) Permit(perm string) error {
	if err := r.Role.Permit(perm); err != nil {
		return err
	}

	r.UpdateCache()
	return nil
}

func (r *CachedRole) Revoke(perm string) error {
	if err := r.Role.Revoke(perm); err != nil {
		return err
	}

	r.UpdateCache()
	return nil
}

func (r *CachedRole) SetParent(role Roler) error {
	c, ok := role.(CachedRoler)
	if !ok {
		return ErrNoCachedRoler
	}

	if err := c.SetChild(r); err != nil {
		return err
	}

	if err := r.Role.SetParent(role); err != nil {
		return err
	}

	r.UpdateCache()
	return nil
}

func (r *CachedRole) RemoveParent(name string) error {
	if p := r.GetParent(name); p != nil {
		cachedP := p.(CachedRoler)
		if err := cachedP.RemoveChild(r.Name()); err != nil {
			return err
		}
	}

	if err := r.Role.RemoveParent(name); err != nil {
		return err
	}

	r.UpdateCache()
	return nil
}

func (r *CachedRole) IsAllowed(perms ...string) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, permisson := range perms {
		if !r.permsCache[permisson] {
			return false
		}
	}

	return true
}
