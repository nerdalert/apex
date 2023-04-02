package nexodus

import "github.com/nexodus-io/nexodus/internal/models"

func (ax *Nexodus) handlePeerRoute(wgPeerConfig wgPeerConfig) {
	if ax.userspaceMode {
		ax.handlePeerRouteUS(wgPeerConfig)
	} else {
		ax.handlePeerRouteOS(wgPeerConfig)
	}
}

func (ax *Nexodus) handlePeerRouteDelete(dev string, wgPeerConfig models.Device) {
	if ax.userspaceMode {
		ax.handlePeerRouteDeleteUS(dev, wgPeerConfig)
	} else {
		ax.handlePeerRouteDeleteOS(dev, wgPeerConfig)
	}
}

func (ax *Nexodus) RouteExists(prefix string) (bool, error) {
	if ax.userspaceMode {
		return RouteExistsUS(prefix)
	} else {
		return RouteExistsOS(prefix)
	}
}
