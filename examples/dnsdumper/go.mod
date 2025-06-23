module github.com/LubyRuffy/tcpdumper/examples/dnsdumper

go 1.24.2

require (
	github.com/LubyRuffy/tcpdumper v0.0.0
	github.com/google/gopacket v1.1.19
)

require golang.org/x/sys v0.0.0-20190412213103-97732733099d // indirect

replace github.com/LubyRuffy/tcpdumper => ../../
