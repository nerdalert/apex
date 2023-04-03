//go:build darwin

package nexodus

import (
	"fmt"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"net"
	"strings"
)

// RouteExistsOS currently only used for darwin build purposes
func RouteExistsOS(s string) (bool, error) {
	return false, nil
}

// AddRoute adds a route to the specified interface
func AddRoute(prefix, dev string) error {
	_, err := RunCommand("route", "-q", "-n", "add", "-inet", prefix, "-interface", dev)
	if err != nil {
		return fmt.Errorf("v4 route add failed: %w", err)
	}

	return nil
}

// AddRouteV6 adds a route to the specified interface
func AddRouteV6(prefix, dev string) error {
	_, err := RunCommand("route", "-q", "-n", "add", "-inet6", prefix, "-interface", dev)
	if err != nil {
		return fmt.Errorf("v6 route add failed: %w", err)
	}

	return nil
}

// discoverLinuxAddress only used for darwin build purposes
func discoverLinuxAddress(logger *zap.SugaredLogger, family int) (net.IP, error) {
	return nil, nil
}

// deleteIface checks to see if  is an interface exists and deletes it
func linkExists(ifaceName string) bool {
	if _, err := netlink.LinkByName(ifaceName); err != nil {
		return false
	}
	return true
}

// delLink deletes the link and assumes it exists
func delLink(ifaceName string) error {
	if link, err := netlink.LinkByName(ifaceName); err == nil {
		if err = netlink.LinkDel(link); err != nil {
			return err
		}
	}
	return nil
}

// DeleteRoute deletes a darwin route
func DeleteRoute(prefix, dev string) error {
	_, err := RunCommand("route", "-q", "-n", "delete", "-inet", prefix, "-interface", dev)
	if err != nil {
		return fmt.Errorf("no route deleted: %w", err)
	}

	return nil
}

func defaultTunnelDevOS() string {
	return darwinIface
}

// binaryChecks validate the required binaries are available
func binaryChecks() error {
	// Darwin wireguard-go userspace binary
	if !IsCommandAvailable(wgGoBinary) {
		return fmt.Errorf("%s command not found, is wireguard installed?", wgGoBinary)
	}
	return nil
}

// Check OS and report error if the OS is not supported.
func checkOS(logger *zap.SugaredLogger) error {
	// ensure the osx wireguard directory exists
	if err := CreateDirectory(WgDarwinConfPath); err != nil {
		return fmt.Errorf("unable to create the wireguard config directory [%s]: %w", WgDarwinConfPath, err)
	}
	return nil
}

// isIPv6Supported returns true if the platform supports IPv6, return true if ifconfig isn't present for whatever reason
func isIPv6Supported() bool {
	res, err := RunCommand("ifconfig")
	if err != nil {
		return true
	}
	if !strings.Contains(res, "inet6") {
		return false
	}

	return true
}
