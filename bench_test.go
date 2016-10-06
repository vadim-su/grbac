package grbac

import (
	"testing"
	"time"
)

const duration = 10 * time.Millisecond

func BenchmarkChainCheckPermissions(b *testing.B) {
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

	go func() {
		exist := false
		tick := time.Tick(duration)

		for _ = range tick {
			if exist {
				roleE.Revoke("NewPermission")
				exist = false
			} else {
				roleE.Permit("NewPermission")
				exist = true
			}
		}
	}()

	b.ResetTimer()
	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				if !(roleE.IsAllowed(permA) &&
					roleE.IsAllowed(permB) &&
					roleE.IsAllowed(permC) &&
					roleE.IsAllowed(permD) &&
					roleE.IsAllowed(permD1) &&
					roleE.IsAllowed(permE)) {

					b.Error("Expected that RoleE has all permissions")
				}
			}
		})
}

func BenchmarkLineCheckPermissions(b *testing.B) {
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

	go func() {
		exist := false
		tick := time.Tick(duration)

		for _ = range tick {
			if exist {
				roleE.Revoke("NewPermission")
				exist = false
			} else {
				roleE.Permit("NewPermission")
				exist = true
			}
		}
	}()

	b.ResetTimer()
	b.RunParallel(
		func(pb *testing.PB) {
			for pb.Next() {
				if !roleE.IsAllowed(permA, permB, permC, permD, permD1, permE) {
					b.Error("Expected that RoleE has all of these permissions")
				}
			}
		})
}
