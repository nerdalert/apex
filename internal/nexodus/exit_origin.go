package nexodus

import (
	"fmt"
	"go.uber.org/zap"
)

// Origin netfilter and forwarding configuration
// sysctl -w net.ipv4.ip_forward=1
// nft add table inet nexodus-exit-node
// nft add chain inet nexodus-exit-node prerouting '{ type nat hook prerouting priority dstnat; }'
// nft add chain inet nexodus-exit-node postrouting '{ type nat hook postrouting priority srcnat; }'
// nft add chain inet nexodus-exit-node forward '{ type filter hook forward priority filter; }'
// nft add rule inet nexodus-exit-node postrouting oifname "<PHYSICAL_IFACE>" counter masquerade
// nft add rule inet nexodus-exit-node forward iifname "wg0" counter accept

func addExitDestinationTable(logger *zap.SugaredLogger) error {
	if _, err := policyCmd(logger, []string{"add", "table", "inet", nfExitNodeTable}); err != nil {
		return fmt.Errorf("failed to add nftables table %s: %w", nfExitNodeTable, err)
	}

	return nil
}

func addExitOriginPreroutingChain(logger *zap.SugaredLogger) error {
	if _, err := policyCmd(logger, []string{"add", "chain", "inet", nfExitNodeTable, "prerouting", "{", "type", "nat", "hook", "prerouting", "priority", "dstnat", ";", "}"}); err != nil {
		return fmt.Errorf("failed to add nftables chain nexodus-exit-node: %w", err)
	}

	return nil
}

func addExitOriginPostroutingChain(logger *zap.SugaredLogger) error {
	if _, err := policyCmd(logger, []string{"add", "chain", "inet", nfExitNodeTable, "postrouting", "{", "type", "nat", "hook", "postrouting", "priority", "srcnat", ";", "}"}); err != nil {
		return fmt.Errorf("failed to add nftables chain nexodus-exit-node: %w", err)
	}

	return nil
}

func addExitOriginForwardChain(logger *zap.SugaredLogger) error {
	if _, err := policyCmd(logger, []string{"add", "chain", "inet", nfExitNodeTable, "forward", "{", "type", "filter", "hook", "forward", "priority", "filter", ";", "}"}); err != nil {
		return fmt.Errorf("failed to add nftables chain nexodus-exit-node: %w", err)
	}

	return nil
}

func addExitOriginPostroutingRule(logger *zap.SugaredLogger, phyIface string) error {
	if _, err := policyCmd(logger, []string{"add", "rule", "inet", nfExitNodeTable, "postrouting", "oifname", phyIface, "masquerade"}); err != nil {
		return fmt.Errorf("failed to add nftables rule nexodus-exit-node: %w", err)
	}

	return nil
}

func addExitOriginForwardRule(logger *zap.SugaredLogger) error {
	if _, err := policyCmd(logger, []string{"add", "rule", "inet", nfExitNodeTable, "forward", "iifname", wgIface, "accept"}); err != nil {
		return fmt.Errorf("failed to add nftables rule nexodus-exit-node: %w", err)
	}

	return nil
}

//func (nx *Nexodus) updateExitNodeOrigins(newPeer wgPeerConfig) {
//	nx.exitNode.exitNodeExists = true
//	// check if the exit node already exists and update its details
//	found := false
//	for i, existingPeerConfig := range nx.exitNode.exitNodeOrigins {
//		if existingPeerConfig.PublicKey == newPeer.PublicKey {
//			nx.exitNode.exitNodeOrigins[i].Endpoint = newPeer.Endpoint
//			found = true
//			break
//		}
//	}
//
//	// If no existing entry with the same public key was found, append the new exit node
//	if !found {
//		nx.exitNode.exitNodeOrigins = append(nx.exitNode.exitNodeOrigins, newPeer)
//	}
//}

func (nx *Nexodus) updateExitNodeOrigins(newPeer wgPeerConfig) {
	nx.exitNode.exitNodeExists = true

	// Debug: Print the received newPeer
	fmt.Printf("Received newPeer: %+v\n", newPeer)

	// Flag to indicate if a peer with the same public key is found
	found := false

	// Loop through the existing exitNodeOrigins
	for i, existingPeerConfig := range nx.exitNode.exitNodeOrigins {
		// Debug: Print existing peer config
		fmt.Printf("Comparing with existingPeer: %+v\n", existingPeerConfig)

		if existingPeerConfig.PublicKey == newPeer.PublicKey {
			// Debug: Print match found
			fmt.Println("Match found, updating Endpoint.")

			// Update the endpoint if the public key already exists
			nx.exitNode.exitNodeOrigins[i].Endpoint = newPeer.Endpoint
			found = true
			break
		}
	}

	// If no existing entry with the same public key was found, append the new wgPeerConfig
	if !found {
		// Debug: Print appending new peer
		fmt.Println("No match found, appending new peer.")

		nx.exitNode.exitNodeOrigins = append(nx.exitNode.exitNodeOrigins, newPeer)
	}

	// Debug: Print the updated list
	fmt.Printf("Updated list: %+v\n", nx.exitNode.exitNodeOrigins)
}
