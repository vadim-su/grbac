package grbac

import (
	"math/rand"
	"strconv"
	"testing"
	"time"
)

func generateHierarchy(newFunc NewFunc, countParents, deep, countPerms int) Roler {
	root := newFunc("root")
	generateLevels(newFunc, root, countParents, deep, countPerms)
	return root
}

func generateLevels(newFunc NewFunc, root Roler, countParents, deep, countPerms int) {
	if deep <= 0 {
		return
	}
	for _, role := range generateRoles(newFunc, root.Name()+".lvl"+strconv.Itoa(deep), countParents, countPerms) {
		generateLevels(newFunc, role, countParents, deep-1, countPerms)
		if err := root.SetParent(role); err != nil {
			panic(err)
		}
	}
}

func generateRoles(newFunc NewFunc, prefix string, count, countPerms int) (roles []Roler) {
	roles = make([]Roler, count)
	for index := 0; index < count; index++ {
		roleName := prefix + "_" + strconv.Itoa(index)
		role := &roles[index]
		*role = newFunc(roleName)

		for permIndex := 0; permIndex < countPerms; permIndex++ {
			(*role).Permit("perm_" + roleName + "_" + strconv.Itoa(permIndex))
		}
	}
	return
}

func randomChoicePerm(perms []string) string {
	rand.Seed(time.Now().Unix())
	return perms[rand.Intn(len(perms))]
}

func randomChoiceParents(roles []Roler) Roler {
	rand.Seed(time.Now().Unix())
	return roles[rand.Intn(len(roles))]
}

func getPermissionsList(perms map[string]bool) []string {
	permList := make([]string, len(perms))
	iter := 0

	for perm := range perms {
		permList[iter] = perm
		iter++
	}

	return permList
}

func getParentsList(roles map[string]Roler) []Roler {
	rolesList := make([]Roler, len(roles))
	iter := 0

	for _, role := range roles {
		rolesList[iter] = role
		iter++
	}

	return rolesList
}

func getParentOnLvl(root Roler, deep int) Roler {
	parents := root.AllParents()
	if (deep != 0) && (len(parents) > 0) {
		nextP := randomChoiceParents(getParentsList(parents))
		return getParentOnLvl(nextP, deep-1)
	}

	return root
}

func chainCheckPermissions(newFunc NewFunc, countParents, deep, countPerms, choiceLvl int, b *testing.B) {
	rootRole := generateHierarchy(newFunc, countParents, deep, countPerms)

	permAList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permA := randomChoicePerm(getPermissionsList(permAList))

	permBList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permB := randomChoicePerm(getPermissionsList(permBList))

	permCList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permC := randomChoicePerm(getPermissionsList(permCList))

	permDList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permD := randomChoicePerm(getPermissionsList(permDList))

	permEList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permE := randomChoicePerm(getPermissionsList(permEList))

	permFList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permF := randomChoicePerm(getPermissionsList(permFList))

	b.ResetTimer()
	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				if !(rootRole.IsAllowed(permA) &&
					rootRole.IsAllowed(permB) &&
					rootRole.IsAllowed(permC) &&
					rootRole.IsAllowed(permD) &&
					rootRole.IsAllowed(permE) &&
					rootRole.IsAllowed(permF)) {

					b.Error("Expected that rootRole has all permissions")
				}
			}
		})
}

func lineCheckPermissions(newFunc NewFunc, countParents, deep, countPerms, choiceLvl int, b *testing.B) {
	rootRole := generateHierarchy(newFunc, countParents, deep, countPerms)

	permAList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permA := randomChoicePerm(getPermissionsList(permAList))

	permBList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permB := randomChoicePerm(getPermissionsList(permBList))

	permCList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permC := randomChoicePerm(getPermissionsList(permCList))

	permDList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permD := randomChoicePerm(getPermissionsList(permDList))

	permEList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permE := randomChoicePerm(getPermissionsList(permEList))

	permFList := getParentOnLvl(rootRole, choiceLvl).Permissions()
	permF := randomChoicePerm(getPermissionsList(permFList))

	b.ResetTimer()
	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				if !rootRole.IsAllowed(permA, permB, permC, permD, permE, permF) {
					b.Error("Expected that rootRole has all permissions")
				}
			}
		})
}

func BenchmarkBigTreeLastLvlDefaultChainCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewRole(name) }
	chainCheckPermissions(newFunc, 10, 5, 10, -1, b)
}

func BenchmarkBigTreeLastLvlCachedChainCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewCachedRole(name) }
	chainCheckPermissions(newFunc, 10, 5, 10, -1, b)
}

func BenchmarkBigTreeMidLvlDefaultChainCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewRole(name) }
	chainCheckPermissions(newFunc, 10, 5, 10, 3, b)
}

func BenchmarkBigTreeMidLvlCachedChainCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewCachedRole(name) }
	chainCheckPermissions(newFunc, 10, 5, 10, 3, b)
}

func BenchmarkBigTreeStartLvlDefaultChainCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewRole(name) }
	chainCheckPermissions(newFunc, 10, 5, 10, 1, b)
}

func BenchmarkBigTreeStartLvlCachedChainCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewCachedRole(name) }
	chainCheckPermissions(newFunc, 10, 5, 10, 1, b)
}

func BenchmarkBigTreeLastLvlDefaultLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewRole(name) }
	lineCheckPermissions(newFunc, 10, 5, 10, -1, b)
}

func BenchmarkBigTreeLastLvlCachedLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewCachedRole(name) }
	lineCheckPermissions(newFunc, 10, 5, 10, -1, b)
}

func BenchmarkBigTreeMidLvlDefaultLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewRole(name) }
	lineCheckPermissions(newFunc, 10, 5, 10, 3, b)
}

func BenchmarkBigTreeMidLvlCachedLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewCachedRole(name) }
	lineCheckPermissions(newFunc, 10, 5, 10, 3, b)
}

func BenchmarkBigTreeStartLvlDefaultLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewRole(name) }
	lineCheckPermissions(newFunc, 10, 5, 10, 1, b)
}

func BenchmarkBigTreeStartLvlCachedLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewCachedRole(name) }
	lineCheckPermissions(newFunc, 10, 5, 10, 1, b)
}

func BenchmarkGrandOneLvlDefaultLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewRole(name) }
	lineCheckPermissions(newFunc, 100000, 1, 10, -1, b)
}

func BenchmarkGrandOneLvlCachedLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewCachedRole(name) }
	lineCheckPermissions(newFunc, 100000, 1, 10, -1, b)
}

func BenchmarkLongInheritChainDefaultLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewRole(name) }
	lineCheckPermissions(newFunc, 1, 1000, 1, -1, b)
}

func BenchmarkLongInheritChainLvlCachedLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewCachedRole(name) }
	lineCheckPermissions(newFunc, 1, 1000, 1, -1, b)
}

func BenchmarkGrandPermsListDefaultLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewRole(name) }
	lineCheckPermissions(newFunc, 1, 1, 100000, -1, b)
}

func BenchmarkGrandPermsListLvlCachedLineCheckPermissions(b *testing.B) {
	newFunc := func(name string) Roler { return NewCachedRole(name) }
	lineCheckPermissions(newFunc, 1, 1, 100000, -1, b)
}
