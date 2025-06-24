module github.com/LubyRuffy/tcpdumper/examples/rawtcpdumper

go 1.24.2

require (
	github.com/LubyRuffy/tcpdumper v0.0.0
	github.com/google/gopacket v1.1.20-0.20250319234736-b7d9dbd15ae4
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.0.0-20200217220822-9197077df867 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/LubyRuffy/tcpdumper => ../../
