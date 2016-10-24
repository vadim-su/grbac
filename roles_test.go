package grbac

import "testing"

type NewFunc func(string) Roler

func newRole(name string) Roler {
	return NewRole(name)
}

func newCachedRole(name string) Roler {
	return NewCachedRole(name)
}

func setPermissions(newFunc NewFunc, t *testing.T) {
	permOpenSite := "OpenSite"
	permSendMsg := "SendMsg"
	permEditMsg := "EditMsg"
	roleUser := newFunc("User")

	roleUser.Permit(permOpenSite)
	roleUser.Permit(permSendMsg)
	roleUser.Permit(permEditMsg)

	perms := roleUser.Permissions()
	if !(perms[permOpenSite] && perms[permSendMsg] && perms[permEditMsg]) {
		t.Error("expected that role User has all of these permissions")
	}

	err := roleUser.Permit(permSendMsg)
	if err == nil {
		t.Errorf("expected \"%v\"", ErrRoleHasPerm)
	}
}

func revokePermissions(newFunc NewFunc, t *testing.T) {
	permOpenSite := "OpenSite"
	permSendMsg := "SendMsg"
	permEditMsg := "EditMsg"
	roleUser := newFunc("User")

	roleUser.Permit(permOpenSite)
	roleUser.Permit(permSendMsg)
	roleUser.Permit(permEditMsg)

	roleUser.Revoke(permOpenSite)
	roleUser.Revoke(permEditMsg)

	perms := roleUser.Permissions()
	if !perms[permSendMsg] || perms[permOpenSite] || perms[permEditMsg] {
		t.Errorf("expected that role User has %v permission", permSendMsg)
		t.Log(perms)
	}

	err := roleUser.Revoke(permOpenSite)
	if err == nil {
		t.Errorf("expected \"%v\"", ErrRoleNotPerm)
	}
}

func setParents(newFunc NewFunc, t *testing.T) {
	roleGeneral := newFunc("General")

	roleNotApproved := newFunc("NotApproved")
	err := roleNotApproved.SetParent(roleGeneral)
	if err != nil {
		t.Fatal(err)
	}

	roleUser := newFunc("User")
	err = roleUser.SetParent(roleNotApproved)
	if err != nil {
		t.Fatal(err)
	}

	roleAdmin := newFunc("Admin")

	err = roleAdmin.SetParent(roleUser)
	if err != nil {
		t.Fatal(err)
	}

	parents := roleAdmin.AllParents()

	onError := func(name string) {
		t.Errorf("AllParents method returned an incorrect value:"+
			" name \"%v\" not found", name)
	}

	if _, generalOk := parents[roleGeneral.Name()]; !generalOk {
		onError(roleGeneral.Name())
	}

	if _, NAOk := parents[roleNotApproved.Name()]; !NAOk {
		onError(roleNotApproved.Name())
	}

	if _, userOk := parents[roleUser.Name()]; !userOk {
		onError(roleUser.Name())
	}
}

func removeParents(newFunc NewFunc, t *testing.T) {
	roleGeneral := newFunc("General")

	roleNotApproved := newFunc("NotApproved")
	err := roleNotApproved.SetParent(roleGeneral)
	if err != nil {
		t.Fatal(err)
	}

	roleUser := newFunc("User")
	err = roleUser.SetParent(roleNotApproved)
	if err != nil {
		t.Fatal(err)
	}

	roleAdmin := newFunc("Admin")

	err = roleAdmin.SetParent(roleUser)
	if err != nil {
		t.Fatal(err)
	}

	err = roleUser.RemoveParent(roleNotApproved.Name())
	if err != nil {
		t.Error(err)
	}

	parents := roleAdmin.AllParents()

	if _, ok := parents[roleUser.Name()]; !ok {
		t.Error("expected that Admin role includes role User")
	}

	if _, ok := parents[roleNotApproved.Name()]; ok {
		t.Error("expected Admin role does not include NotApproved role")
	}

	if _, ok := parents[roleGeneral.Name()]; ok {
		t.Error("expected Admin role does not include General role")
	}

	err = roleUser.RemoveParent(roleNotApproved.Name())

	if err != ErrNoParent {
		t.Errorf("expected \"%v\"", ErrNoParent)
	}
}

func hasParent(newFunc NewFunc, t *testing.T) {
	roleGeneral := newFunc("General")

	roleNotApproved := newFunc("NotApproved")
	err := roleNotApproved.SetParent(roleGeneral)
	if err != nil {
		t.Fatal(err)
	}

	roleUser := newFunc("User")
	err = roleUser.SetParent(roleNotApproved)
	if err != nil {
		t.Fatal(err)
	}

	roleAdmin := newFunc("Admin")
	err = roleAdmin.SetParent(roleUser)
	if err != nil {
		t.Fatal(err)
	}

	if !roleAdmin.HasParent(roleUser.Name()) {
		t.Errorf("expected that Admin role has User role in parents")
	}

	err = roleAdmin.RemoveParent(roleUser.Name())
	if err != nil {
		t.Error(err)
	}

	if roleAdmin.HasParent(roleUser.Name()) {
		t.Errorf("expected that Admin role doers not have User role in parents now")
	}
}

func getParent(newFunc NewFunc, t *testing.T) {
	permA := "PermA"
	permB := "PermB"

	roleA := newFunc("RoleA")
	roleA.Permit(permA)

	roleB := newFunc("RoleB")
	roleB.Permit(permB)
	roleB.SetParent(roleA)

	if p := roleB.GetParent(roleA.Name()); p == nil {
		t.Errorf("expected that RoleB has RoleA as a perent")
		t.Logf("RoleB parents: %v", roleB.AllParents())

	}

	if p := roleB.GetParent("No Role!"); p != nil {
		t.Errorf("expected that RoleB does not have \"No Role\" in the parents")
		t.Logf("RoleB parents: %v", roleB.AllParents())

	}

	roleB.RemoveParent(roleA.Name())

	if p := roleB.GetParent(roleA.Name()); p != nil {
		t.Errorf("expected that RoleB does not have \"No Role\" in the parents")
		t.Logf("RoleB parents: %v", roleB.AllParents())
	}
}

func setPermissionsForMultipleParents(newFunc NewFunc, t *testing.T) {
	permGeneral := "GeneralPerm"
	permNotApproved := "NotApprovedPerm"
	permUser := "UserPerm"
	permAdmin := "AdminPerm"

	roleGeneral := newFunc("General")
	err := roleGeneral.Permit(permGeneral)
	if err != nil {
		t.Error(err)
	}

	roleNotApproved := newFunc("NotApproved")
	err = roleNotApproved.SetParent(roleGeneral)
	if err != nil {
		t.Fatal(err)
	}

	err = roleNotApproved.Permit(permNotApproved)
	if err != nil {
		t.Error(err)
	}

	roleUser := newFunc("User")
	err = roleUser.SetParent(roleNotApproved)
	if err != nil {
		t.Fatal(err)
	}

	err = roleUser.Permit(permUser)
	if err != nil {
		t.Error(err)
	}

	roleAdmin := newFunc("Admin")
	err = roleAdmin.Permit(permAdmin)
	if err != nil {
		t.Error(err)
	}

	err = roleAdmin.SetParent(roleUser)
	if err != nil {
		t.Fatal(err)
	}

	if p := roleAdmin.Permissions(); !(p[permAdmin] && !p[permGeneral]) {
		t.Errorf("expected that role Admin has only %v permission", permAdmin)
	}

	perms := roleAdmin.AllPermissions()

	if !(perms[permGeneral] &&
		perms[permNotApproved] &&
		perms[permUser] &&
		perms[permAdmin]) {
		t.Error("expected that role Admin has all of these permissions")
		t.Log(perms)
	}

	err = roleAdmin.SetParent(roleUser)
	if err == nil {
		t.Errorf("expected \"%v\"", err)
	}
}

func isAllowedMultipleArguments(newFunc NewFunc, t *testing.T) {
	permA := "PermA"
	permB := "PermB"
	permC := "PermC"
	permD := "PermD"
	permD1 := "PermD1"
	permE := "PermE"

	roleA := newFunc("RoleA")
	roleA.Permit(permA)

	roleB := newFunc("RoleB")
	roleB.Permit(permB)

	roleC := newFunc("RoleC")
	roleC.Permit(permC)
	roleC.SetParent(roleA)
	roleC.SetParent(roleB)

	roleD := newFunc("RoleD")
	roleD.Permit(permD)
	roleD.Permit(permD1)
	roleD.SetParent(roleA)
	roleD.SetParent(roleC)

	roleE := newFunc("RoleE")
	roleE.Permit(permE)
	roleE.SetParent(roleA)
	roleE.SetParent(roleC)
	roleE.SetParent(roleD)

	if !roleE.IsAllowed(permA, permB, permC, permD, permD1, permE) {
		t.Errorf("expected that RoleE has all the necessary privileges")
		t.Logf("RoleE: %v", roleE.AllPermissions())
	}

	roleE.RemoveParent(roleD.Name())

	if roleE.IsAllowed(permA, permB, permC, permD, permD1, permE) {
		t.Errorf("expected that RoleE does not have all necessary permissions")
		t.Logf("RoleE: %v", roleE.AllPermissions())
	}
}

func TestDefaultRoleSetPermissions(t *testing.T) {
	setPermissions(newRole, t)
}

func TestCachedRoleSetPermissions(t *testing.T) {
	setPermissions(newCachedRole, t)
}

func TestDefaultRoleRevokePermissions(t *testing.T) {
	revokePermissions(newRole, t)
}

func TestCachedRoleRevokePermissions(t *testing.T) {
	revokePermissions(newCachedRole, t)
}

func TestDefaultRoleSetParent(t *testing.T) {
	setParents(newRole, t)
}

func TestCachedRoleSetParent(t *testing.T) {
	setParents(newCachedRole, t)
}

func TestDefaultRoleRemoveParent(t *testing.T) {
	removeParents(newRole, t)
}

func TestCachedRoleRemoveParent(t *testing.T) {
	removeParents(newCachedRole, t)
}

func TestDefaultRoleHasParent(t *testing.T) {
	hasParent(newRole, t)
}

func TestCachedRoleHasParent(t *testing.T) {
	hasParent(newCachedRole, t)
}

func TestDefaultRoleGetParent(t *testing.T) {
	getParent(newRole, t)
}

func TestCachedRoleGetParent(t *testing.T) {
	getParent(newCachedRole, t)
}

func TestDefaultRoleSetPermissionsForMultipleParents(t *testing.T) {
	setPermissionsForMultipleParents(newRole, t)
}

func TestCachedRoleSetPermissionsForMultipleParents(t *testing.T) {
	setPermissionsForMultipleParents(newCachedRole, t)
}

func TestDefaultRoleIsAllowedMultipleArguments(t *testing.T) {
	isAllowedMultipleArguments(newRole, t)
}

func TestCachedRoleIsAllowedMultipleArguments(t *testing.T) {
	isAllowedMultipleArguments(newCachedRole, t)
}

}
