package iptables

import (
	"regexp"
	"strconv"
	"strings"

	"iptables-web/internal/model"
)

var (
	chainHeaderRe  = regexp.MustCompile(`^Chain (\S+) \(policy (\S+) .*`)
	ruleLineRe     = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)`)
	chainHeader2Re = regexp.MustCompile(`^Chain (\S+) .*pkts bytes target.*`)
)

// ParseChains extracts chain names from iptables -L output.
func ParseChains(output string) []string {
	var chains []string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "Chain ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				chains = append(chains, parts[1])
			}
		}
	}
	return chains
}

// ParseChainOutput parses iptables -L -n -v --line-numbers output into structured data.
func ParseChainOutput(output string) ([]model.ChainInfo, error) {
	var chains []model.ChainInfo
	var current *model.ChainInfo

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, " \t\r")

		if strings.HasPrefix(line, "Chain ") {
			if current != nil {
				chains = append(chains, *current)
			}
			current = &model.ChainInfo{}
			if m := chainHeaderRe.FindStringSubmatch(line); m != nil {
				current.Name = m[1]
				current.Policy = m[2]
			} else if m2 := chainHeader2Re.FindStringSubmatch(line); m2 != nil {
				current.Name = m2[1]
				current.Policy = "ACCEPT"
			}
			continue
		}

		if current == nil || strings.TrimSpace(line) == "" {
			continue
		}

		if m := ruleLineRe.FindStringSubmatch(line); m != nil {
			num, _ := strconv.Atoi(m[1])
			pkts, _ := strconv.ParseInt(m[2], 10, 64)
			byts, _ := strconv.ParseInt(m[3], 10, 64)
			pr := model.ParsedRule{
				Num:     num,
				Pkts:    pkts,
				Bytes:   byts,
				Target:  m[4],
				Prot:    m[5],
				Opt:     m[6],
				In:      m[7],
				Out:     m[8],
				Source:  m[9],
				Dest:    m[10],
				Options: strings.TrimSpace(m[11]),
			}
			current.Rules = append(current.Rules, pr)
			current.PacketCount += pkts
			current.ByteCount += byts
		}
	}

	if current != nil {
		chains = append(chains, *current)
	}
	return chains, nil
}
