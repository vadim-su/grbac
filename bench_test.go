package grbac

import (
	"sync"
	"testing"
	"time"
)

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
		for {
			roleE.Permit("NewPermission")
			time.Sleep(5 * time.Millisecond)
		}
	}()

	go func() {
		for {
			roleE.Revoke("NewPermission")
			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(b.N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() {
			if !(roleE.IsAllowed(permA) &&
				roleE.IsAllowed(permB) &&
				roleE.IsAllowed(permC) &&
				roleE.IsAllowed(permD) &&
				roleE.IsAllowed(permD1) &&
				roleE.IsAllowed(permE)) {
				b.Error("Expected that RoleE has all permissions")
			}
			wg.Done()
		}()
	}
	wg.Wait()

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
		for {
			roleE.Permit("NewPermission")
			time.Sleep(5 * time.Millisecond)
		}
	}()

	go func() {
		for {
			roleE.Revoke("NewPermission")
			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg := sync.WaitGroup{}
	wg.Add(b.N)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		go func() {
			if !roleE.IsAllowed(permA, permB, permC, permD, permD1, permE) {
				b.Error("Expected that RoleE has all of these permissions")
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
