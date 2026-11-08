package policy

import "regexp"

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidStationID reports whether id is safe for MQTT topics.
func ValidStationID(id string) bool {
	return idRE.MatchString(id)
}

// ValidTenantID reports whether id is safe for MQTT topics.
func ValidTenantID(id string) bool {
	return idRE.MatchString(id)
}

// StationAllowsProtocol reports whether station may use protocol.
// Empty protocols allows wu and ecowitt.
func StationAllowsProtocol(protocols []string, protocol string) bool {
	if len(protocols) == 0 {
		return true
	}
	for _, p := range protocols {
		if p == protocol {
			return true
		}
	}
	return false
}
