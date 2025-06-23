module github.com/LubyRuffy/tcpdumper/examples/httpdumper

go 1.24.2

require (
	github.com/LubyRuffy/tcpdumper v0.0.0
	github.com/google/gopacket v1.1.20-0.20250319234736-b7d9dbd15ae4
)

require golang.org/x/sys v0.0.0-20200217220822-9197077df867 // indirect

replace github.com/LubyRuffy/tcpdumper => ../../
