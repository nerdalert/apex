package apex

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/pion/stun"
	"go.uber.org/zap"
)

// OperatingSystem supported OS types
type OperatingSystem string

const (
	Linux   OperatingSystem = "Linux"
	Darwin  OperatingSystem = "Darwin"
	Windows OperatingSystem = "Windows"
)

func (operatingSystem OperatingSystem) String() string {
	switch operatingSystem {
	case Linux:
		return "linux"
	case Darwin:
		return "darwin"
	case Windows:
		return "windows"
	}

	return "unsupported"
}

// GetOS get os type
func GetOS() (operatingSystem string) {
	return runtime.GOOS
}

// RunCommand runs the cmd and returns the combined stdout and stderr
func RunCommand(cmd ...string) (string, error) {
	output, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to run %q: %s (%s)", strings.Join(cmd, " "), err, output)
	}
	return string(output), nil
}

// IsCommandAvailable checks to see if a binary is available in the current path
func IsCommandAvailable(name string) bool {
	if _, err := exec.LookPath(name); err != nil {
		return false
	}
	return true
}

// ValidateIp ensures a valid IP4/IP6 address is provided
func ValidateIp(ip string) error {
	if ip := net.ParseIP(ip); ip != nil {
		return nil
	}
	return fmt.Errorf("%s is not a valid v4 or v6 IP", ip)
}

// ValidateCIDR ensures a valid IP4/IP6 prefix is provided
func ValidateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%s is not a valid v4 or v6 IP prefix", err)
	}
	return nil
}

// discoverGenericIPv4 opens a socket to the controller and returns the IP of the source dial
func discoverGenericIPv4(logger *zap.SugaredLogger, controller string, port string) (string, error) {
	controllerSocket := fmt.Sprintf("%s:%s", controller, port)
	conn, err := net.Dial("udp", controllerSocket)
	if err != nil {
		return "", err
	}
	conn.Close()
	ipAddress := conn.LocalAddr().(*net.UDPAddr)
	if ipAddress != nil {
		ipPort := strings.Split(ipAddress.String(), ":")
		logger.Debugf("Nodes discovered local address is [%s]", ipPort[0])
		return ipPort[0], nil
	}
	return "", fmt.Errorf("failed to obtain the local IP")
}

// GetPubIPv4 retrieves current global IP address using STUN
func GetPubIPv4(logger *zap.SugaredLogger) (string, error) {
	// Creating a "connection" to STUN server.
	c, err := stun.Dial("udp4", "stun.l.google.com:19302")
	if err != nil {
		logger.Error(err)
		return "", err
	}

	// Building binding request with random transaction id.
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	var ourIP string
	// Sending request to STUN server, waiting for response message.
	if err := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			logger.Error(res.Error)
			return
		}
		// Decoding XOR-MAPPED-ADDRESS attribute from message.
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err != nil {
			return
		}
		logger.Debug("STUN: your IP is: ", xorAddr.IP)
		ourIP = xorAddr.IP.String()
	}); err != nil {
		logger.Error(err)
		return "", err
	}

	return ourIP, nil
}

func IsNAT(logger *zap.SugaredLogger, nodeOS, controller string, port string) (bool, error) {
	var hostIP string
	var err error
	if nodeOS == Darwin.String() {
		hostIP, err = discoverGenericIPv4(logger, controller, port)
		if err != nil {
			return false, err
		}
	}
	if nodeOS == Windows.String() {
		hostIP, err = discoverGenericIPv4(logger, controller, port)
		if err != nil {
			return false, err
		}
	}
	if nodeOS == Linux.String() {
		linuxIP, err := discoverLinuxAddress(logger, 4)
		if err != nil {
			return false, err
		}
		hostIP = linuxIP.String()
	}
	pubIP, err := GetPubIPv4(logger)
	if err != nil {
		return false, err
	}
	if hostIP != pubIP {
		return true, nil
	}
	return false, nil
}

// CreateDirectory create a directory if one does not exist
func CreateDirectory(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create the directory %s: %v", path, err)
		}
	}
	return nil
}

func FileExists(f string) bool {
	if _, err := os.Stat(f); err != nil {
		return false
	}
	return true
}

// ParseIPNet return an IPNet from a string
func ParseIPNet(s string) (*net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	return &net.IPNet{IP: ip, Mask: ipNet.Mask}, nil
}

func parseNetworkStr(cidr string) (string, error) {
	_, nw, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	return nw.String(), nil
}

// enableForwardingIPv4 for linux nodes that are hub bouncers
func enableForwardingIPv4(logger *zap.SugaredLogger) error {
	cmdOut, err := RunCommand("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err != nil {
		return fmt.Errorf("failed to enable IP Forwarding for this hub-router: %v\n", err)
	}
	logger.Debugf("%v", cmdOut)
	return nil
}

// writeToFile overwrite the contents of a file
func writeToFile(logger *zap.SugaredLogger, s, file string, filePermissions int) {
	// overwrite the existing file contents
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(filePermissions))
	if err != nil {
		logger.Warnf("Unable to open a key file to write to: %v", err)
	}

	defer func(f *os.File) {
		err = f.Close()
		if err != nil {
			logger.Warnf("Unable to write key to file [ %s ] %v", file, err)
		}
	}(f)

	wr := bufio.NewWriter(f)
	_, err = wr.WriteString(s)
	if err != nil {
		logger.Warnf("Unable to write key to file [ %s ] %v", file, err)
	}
	if err = wr.Flush(); err != nil {
		logger.Warnf("Unable to write key to file [ %s ] %v", file, err)
	}
}

// getInterfaceByIP will looks ip an interface by the IP provided
func getInterfaceByIP(ip net.IP) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range interfaces {
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if ifaceIP, _, err := net.ParseCIDR(addr.String()); err == nil {
					if ifaceIP.Equal(ip) {
						return iface.Name, nil
					}
				} else {
					continue
				}
			}
		} else {
			continue
		}
	}
	return "", fmt.Errorf("no interface was found for the ip %s", ip)
}

func setupDarwinIface(logger *zap.SugaredLogger, localAddress string) error {
	_, err := RunCommand("wireguard-go", darwinIface)
	if err != nil {
		logger.Errorf("failed to create the %s interface: %v\n", darwinIface, err)
	}

	_, err = RunCommand("ifconfig", darwinIface, "inet", localAddress, localAddress, "alias")
	if err != nil {
		logger.Errorf("failed to assign an address to the local osx interface: %v\n", err)
	}

	_, err = RunCommand("ifconfig", darwinIface, "up")
	if err != nil {
		logger.Errorf("failed to bring up the %s interface: %v\n", darwinIface, err)
	}

	_, err = RunCommand("wg", "set", darwinIface, "private-key", darwinPrivateKeyFile)
	if err != nil {
		logger.Errorf("failed to start the wireguard listener: %v\n", err)
	}

	return nil
}

// setupLinuxInterface TODO replace with netlink calls
// this is called if this is the first run or if the local node
// address got assigned a new address by the controller
func (ax *Apex) setupLinuxInterface(logger *zap.SugaredLogger) {
	// delete the wireguard ip link interface if it exists
	if ifaceExists(logger, wgIface) {
		_, err := RunCommand("ip", "link", "del", wgIface)
		if err != nil {
			logger.Debugf("failed to delete the ip link interface: %v\n", err)
		}
	}
	// create the wireguard ip link interface
	_, err := RunCommand("ip", "link", "add", wgIface, "type", "wireguard")
	if err != nil {
		logger.Errorf("failed to create the ip link interface: %v\n", err)
	}
	// start the wireguard listener on a well-known port if it is the hub-router as all
	// nodes need to be able to reach this node for state distribution if hole punching.
	if ax.hubRouter {
		_, err = RunCommand("wg", "set", wgIface, "listen-port", strconv.Itoa(WgDefaultPort), "private-key", linuxPrivateKeyFile)
		if err != nil {
			logger.Errorf("failed to start the wireguard listener: %v\n", err)
		}
	} else {
		// start the wireguard listener
		_, err = RunCommand("wg", "set", wgIface, "listen-port", strconv.Itoa(ax.listenPort), "private-key", linuxPrivateKeyFile)
		if err != nil {
			logger.Errorf("failed to start the wireguard listener: %v\n", err)
		}
	}
	// give the wg interface an address
	_, err = RunCommand("ip", "address", "add", ax.wgLocalAddress, "dev", wgIface)
	if err != nil {
		logger.Debugf("failed to assign an address to the local linux interface, attempting to flush the iface: %v\n", err)
		wgIP := getIPv4Iface(wgIface)
		_, err = RunCommand("ip", "address", "del", wgIP.To4().String(), "dev", wgIface)
		if err != nil {
			logger.Errorf("failed to assign an address to the local linux interface: %v\n", err)
		}
		_, err = RunCommand("ip", "address", "add", ax.wgLocalAddress, "dev", wgIface)
		if err != nil {
			logger.Errorf("failed to assign an address to the local linux interface: %v\n", err)
		}
	}
	// bring the wg0 interface up
	_, err = RunCommand("ip", "link", "set", wgIface, "up")
	if err != nil {
		logger.Errorf("failed to bring up the wg interface: %v\n", err)
	}
}

// ifaceExists returns true if the input matches a net interface
func ifaceExists(logger *zap.SugaredLogger, iface string) bool {
	_, err := net.InterfaceByName(iface)
	if err != nil {
		logger.Debug(err)
		return false
	}
	return true
}

// deleteDarwinIface these commands all fail silently so no errors are returned
func deleteDarwinIface(logger *zap.SugaredLogger) {
	tunSock := fmt.Sprintf("/var/run/wireguard/%s.sock", darwinIface)
	_, err := RunCommand("rm", "-f", tunSock)
	if err != nil {
		logger.Debugf("failed to delete darwin interface: %v", err)
	}
	// /var/run/wireguard/wg0.name doesnt currently exist since utun8 isnt mapped to wg0 (fails silently)
	wgName := fmt.Sprintf("/var/run/wireguard/%s.name", wgIface)
	_, err = RunCommand("rm", "-f", wgName)
	if err != nil {
		logger.Debugf("failed to delete darwin interface: %v", err)
	}
}

// getIPv4Iface get the IP of the specified net interface
func getIPv4Iface(ifname string) net.IP {
	interfaces, _ := net.Interfaces()
	for _, inter := range interfaces {
		if inter.Name == ifname {
			if addrs, err := inter.Addrs(); err == nil {
				for _, addr := range addrs {
					switch ip := addr.(type) {
					case *net.IPNet:
						if ip.IP.DefaultMask() != nil {
							return ip.IP
						}
					}
				}
			}
		}
	}
	return nil
}
