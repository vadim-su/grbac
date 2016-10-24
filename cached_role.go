package grbac

import (
	"errors"
	"sync"
)

var (
	ErrNoChild       = errors.New("child does not exist")
	ErrNoCachedRoler = errors.New("parent is not CachedRoler!")
)

type CachedRoler interface {
	Roler
	Children() map[string]CachedRoler
	SetChild(CachedRoler)
	RemoveChild(string)
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

func (r *CachedRole) SetChild(child CachedRoler) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	r.children[child.Name()] = child
}

func (r *CachedRole) RemoveChild(name string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	delete(r.children, name)
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

	c.SetChild(r)

	if err := r.Role.SetParent(role); err != nil {
		return err
	}

	r.UpdateCache()
	return nil
}

func (r *CachedRole) RemoveParent(name string) error {
	if p := r.GetParent(name); p != nil {
		cachedP := p.(CachedRoler)
		cachedP.RemoveChild(r.Name())
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
