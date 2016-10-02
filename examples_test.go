package grbac

import "fmt"

func ExampleRole_simple() {
	// Create a new role
	roleU := NewRole("User")

	// Add the permissions to the role
	roleU.Permit("CreateMsg")
	roleU.Permit("ReadMsg")

	// Check the permission
	if roleU.IsAllowed("ReadMsg") {
		fmt.Println("ReadMsg permission is allowed in the User role")
	}
	// Output: ReadMsg permission is allowed in the User role
}

func ExampleRole() {
	// Define new permissions
	permA := "PermA"
	permB := "PermB"
	permC := "PermC"
	permD := "PermD"
	permD1 := "PermD1"
	permE := "PermE"

	// Create new roles and bind to them the permissions and parents
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

	// Check the permission
	if roleE.IsAllowed(permA, permB, permC, permD, permD1, permE) {
		fmt.Println("All permissions are allowed in the RoleE role")
	}
	// Output: All permissions are allowed in the RoleE role
}

func ExampleRole_SetParent() {
	roleU := NewRole("User")
	roleU.Permit("CreateMsg")
	roleU.Permit("ReadMsg")

	roleA := NewRole("Admin")
	roleA.SetParent(roleU)
	roleA.Permit("EditMsg")
	roleA.Permit("DelMsg")

	if roleA.IsAllowed("CreateMsg", "ReadMsg", "EditMsg", "DelMsg") {
		fmt.Println("All permissions are allowed in the Admin role")
	}
	// Output: All permissions are allowed in the Admin role
}
