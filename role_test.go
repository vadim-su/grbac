package grbac

import "testing"

func TestRoleSetPermissions(t *testing.T) {
	permOpenSite := "OpenSite"
	permSendMsg := "SendMsg"
	permEditMsg := "EditMsg"
	roleUser := NewRole("User")

	roleUser.Permit(permOpenSite)
	roleUser.Permit(permSendMsg)
	roleUser.Permit(permEditMsg)

	perms := roleUser.Permissions()
	if !(perms[permOpenSite] && perms[permSendMsg] && perms[permEditMsg]) {
		t.Error("expected that role User has all of these permissions")
	}

	err := roleUser.Permit(permSendMsg)
	if err == nil {
		t.Errorf("expected \"%v\"", ErrRoleHasAlreadyPerm)
	}
}

func TestRoleRevokePermissions(t *testing.T) {
	permOpenSite := "OpenSite"
	permSendMsg := "SendMsg"
	permEditMsg := "EditMsg"
	roleUser := NewRole("User")

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

func TestRoleSetParents(t *testing.T) {
	roleGeneral := NewRole("General")

	roleNotApproved := NewRole("NotApproved")
	err := roleNotApproved.SetParent(roleGeneral)
	if err != nil {
		t.Error(err)
	}

	roleUser := NewRole("User")
	err = roleUser.SetParent(roleNotApproved)
	if err != nil {
		t.Error(err)
	}

	roleAdmin := NewRole("Admin")

	err = roleAdmin.SetParent(roleUser)
	if err != nil {
		t.Error(err)
	}

	pNames := getParentsNamesRecursive(roleAdmin)
	parents := roleAdmin.AllParents()

	for _, name := range pNames {
		if _, ok := parents[name]; !ok {
			t.Errorf("AllParents method returned an incorrect value:"+
				" name \"%v\" not found", name)
		}
	}
}

func getParentsNamesRecursive(r Roler) []string {
	var names []string

	for pName, p := range r.Parents() {
		names = append(names, pName)
		subParentNames := getParentsNamesRecursive(p)

		for _, subParentName := range subParentNames {
			names = append(names, subParentName)
		}
	}
	return names
}

func TestRoleRemoveParent(t *testing.T) {
	roleGeneral := NewRole("General")

	roleNotApproved := NewRole("NotApproved")
	err := roleNotApproved.SetParent(roleGeneral)
	if err != nil {
		t.Error(err)
	}

	roleUser := NewRole("User")
	err = roleUser.SetParent(roleNotApproved)
	if err != nil {
		t.Error(err)
	}

	roleAdmin := NewRole("Admin")

	err = roleAdmin.SetParent(roleUser)
	if err != nil {
		t.Error(err)
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

func TestRoleHasParent(t *testing.T) {
	roleGeneral := NewRole("General")

	roleNotApproved := NewRole("NotApproved")
	err := roleNotApproved.SetParent(roleGeneral)
	if err != nil {
		t.Error(err)
	}

	roleUser := NewRole("User")
	err = roleUser.SetParent(roleNotApproved)
	if err != nil {
		t.Error(err)
	}

	roleAdmin := NewRole("Admin")

	err = roleAdmin.SetParent(roleUser)
	if err != nil {
		t.Error(err)
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

func TestRoleSetPermissionsForMultipleParents(t *testing.T) {
	permGeneral := "GeneralPerm"
	permNotApproved := "NotApprovedPerm"
	permUser := "UserPerm"
	permAdmin := "AdminPerm"

	roleGeneral := NewRole("General")
	err := roleGeneral.Permit(permGeneral)
	if err != nil {
		t.Error(err)
	}

	roleNotApproved := NewRole("NotApproved")
	err = roleNotApproved.SetParent(roleGeneral)
	if err != nil {
		t.Error(err)
	}

	err = roleNotApproved.Permit(permNotApproved)
	if err != nil {
		t.Error(err)
	}

	roleUser := NewRole("User")
	err = roleUser.SetParent(roleNotApproved)
	if err != nil {
		t.Error(err)
	}

	err = roleUser.Permit(permUser)
	if err != nil {
		t.Error(err)
	}

	roleAdmin := NewRole("Admin")
	err = roleAdmin.Permit(permAdmin)
	if err != nil {
		t.Error(err)
	}

	err = roleAdmin.SetParent(roleUser)
	if err != nil {
		t.Error(err)
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

func TestRoleIsAllowedMultipleArguments(t *testing.T) {
	permA := "PermA"
	permB := "PermB"
	permC := "PermC"
	permD := "PermD"
	permD1 := "PermD1"
	permE := "PermE"

	roleA := NewRole("RoleA")
	roleA.Permit(permA)

	roleB := NewRole("RoleB")
	roleB.Permit(permB)

	roleC := NewRole("RoleC")
	roleC.Permit(permC)
	roleC.SetParent(roleA)
	roleC.SetParent(roleB)

	roleD := NewRole("RoleD")
	roleD.Permit(permD)
	roleD.Permit(permD1)
	roleD.SetParent(roleA)
	roleD.SetParent(roleC)

	roleE := NewRole("RoleE")
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

func TestRoleGetParent(t *testing.T) {
	permA := "PermA"
	permB := "PermB"

	roleA := NewRole("RoleA")
	roleA.Permit(permA)

	roleB := NewRole("RoleB")
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
