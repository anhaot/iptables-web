package api

import "testing"

func TestParseDockerPortsClassifiesAddressFamilies(t *testing.T) {
	mappings := parseDockerPorts("0.0.0.0:18080->80/tcp, [::]:18080->80/tcp")
	if len(mappings) != 2 {
		t.Fatalf("parseDockerPorts() returned %d mappings: %#v", len(mappings), mappings)
	}
	if mappings[0].Family != "ipv4" || mappings[0].HostIP != "0.0.0.0" {
		t.Fatalf("IPv4 mapping = %#v", mappings[0])
	}
	if mappings[1].Family != "ipv6" || mappings[1].HostIP != "[::]" {
		t.Fatalf("IPv6 mapping = %#v", mappings[1])
	}
}

func TestDockerAddressFamily(t *testing.T) {
	tests := map[string]string{"": "ipv4", "0.0.0.0": "ipv4", "127.0.0.1": "ipv4", "::": "ipv6", "[::1]": "ipv6"}
	for input, want := range tests {
		if got := dockerAddressFamily(input); got != want {
			t.Errorf("dockerAddressFamily(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseDockerPortsSkipsUnpublishedPorts(t *testing.T) {
	mappings := parseDockerPorts("80/tcp, 0.0.0.0:18080->80/tcp")
	if len(mappings) != 1 || mappings[0].HostPort != 18080 || mappings[0].ContainerPort != 80 {
		t.Fatalf("parseDockerPorts() = %#v, want only published 18080->80", mappings)
	}
}

func TestShortDockerIDDoesNotPanicOnUnexpectedInput(t *testing.T) {
	if got := shortDockerID("short"); got != "short" {
		t.Fatalf("shortDockerID() = %q", got)
	}
	if got := shortDockerID("1234567890abcdef"); got != "1234567890ab" {
		t.Fatalf("shortDockerID() = %q", got)
	}
}
