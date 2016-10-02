# GRBAC [![Build Status](https://travis-ci.org/deterok/grbac.svg?branch=master)](https://travis-ci.org/deterok/grbac) [![Coverage Status](https://coveralls.io/repos/github/deterok/grbac/badge.svg?branch=master)](https://coveralls.io/github/deterok/grbac?branch=master) [![GoDoc](https://godoc.org/github.com/deterok/grbac?status.svg)](https://godoc.org/github.com/deterok/grbac)

GRBAC is a fast Golang library provides a role-based access control.

The project is written with a focus on performance, minimalism, and a small number of abstractions.

## Install
Run this command

```sh
go get -v github.com/deterok/grbac
```

## Usage
```go
// Create User role
roleU := NewRole("User")

// Add the permissions to the User role
roleU.Permit("CreateMsg")
roleU.Permit("ReadMsg")

// Create Admin role
roleA := NewRole("Admin")

// Add the permissions to the Admin role
roleA.Permit("EditMsg")
roleA.Permit("DelMsg")

// Set the parent
roleA.SetParent(roleU)

// Check the permissions
if roleA.IsAllowed("CreateMsg", "ReadMsg", "EditMsg", "DelMsg") {
	fmt.Println("All permissions are allowed for the Admin role!")
}
```

More examples in [godoc](https://godoc.org/github.com/deterok/grbac)

## Contributing
Pull requests and stars are welcome. For bugs and feature requests,
please create an issue.

## License
Copyright (C) 2016, Vadim Suharnikov. Released under [the MIT license](LICENSE).
