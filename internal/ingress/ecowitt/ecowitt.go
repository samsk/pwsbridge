package ecowitt

import (
	"strconv"
	"strings"
	"time"

	"github.com/samsk/pwsbridge/internal/obs"
	"github.com/samsk/pwsbridge/internal/units"
)

// ReportPath is the Ecowitt custom server path.
const ReportPath = "/data/report"

var metadata = map[string]struct{}{
	"PASSKEY": {}, "stationtype": {}, "dateutc": {}, "freq": {}, "model": {}, "wh65batt": {},
}

// ApplyParams maps Ecowitt POST form fields onto an observation.
func ApplyParams(params map[string]string, o *obs.Observation) {
	for k, v := range params {
		if _, skip := metadata[k]; skip {
			continue
		}
		key := strings.ToLower(k)
		switch key {
		case "tempf":
			setF(o, "temperature", v)
		case "tempinf":
			setF(o, "indoor_temperature", v)
		case "humidity":
			setPlain(o, "humidity", v)
		case "humidityin":
			setPlain(o, "indoor_humidity", v)
		case "baromrelin":
			setInHg(o, "pressure", v)
		case "baromabsin":
			setInHg(o, "pressure_abs", v)
		case "windspeedmph":
			setMPH(o, "wind_speed", v)
		case "windgustmph":
			setMPH(o, "wind_gust", v)
		case "winddir":
			setPlain(o, "wind_direction", v)
		case "rainratein", "hourlyrainin":
			setIn(o, "rain_past_hour", v)
		case "dailyrainin":
			setIn(o, "rain_daily", v)
		case "weeklyrainin":
			setIn(o, "rain_weekly", v)
		case "monthlyrainin":
			setIn(o, "rain_monthly", v)
		case "yearlyrainin", "totalrainin":
			setIn(o, "rain_yearly", v)
		case "solarradiation":
			setPlain(o, "solar_radiation", v)
		case "uv":
			setPlain(o, "uv_index", v)
		case "dewptf":
			setF(o, "dew_point", v)
		default:
			if !obs.ValidKey(k) {
				continue
			}
			if f, ok := parseFloat(v); ok {
				o.SetReceived(k, f)
			}
		}
	}
}

// ParseDateUTC parses Ecowitt dateutc or returns now.
func ParseDateUTC(v string) time.Time {
	if v == "" || v == "now" {
		return time.Now().UTC()
	}
	t, err := time.ParseInLocation("2006-01-02 15:04:05", strings.ReplaceAll(v, "+", " "), time.UTC)
	if err != nil {
		return time.Now().UTC()
	}
	return t
}

// StationKey returns PASSKEY as the station identity.
func StationKey(params map[string]string) string {
	return params["PASSKEY"]
}

func setF(o *obs.Observation, key, v string) {
	if f, ok := parseFloat(v); ok {
		o.SetReceived(key, units.FToC(f))
	}
}

func setMPH(o *obs.Observation, key, v string) {
	if f, ok := parseFloat(v); ok {
		o.SetReceived(key, units.MPHToKPH(f))
	}
}

func setIn(o *obs.Observation, key, v string) {
	if f, ok := parseFloat(v); ok {
		o.SetReceived(key, units.InchesToMM(f))
	}
}

func setInHg(o *obs.Observation, key, v string) {
	if f, ok := parseFloat(v); ok {
		o.SetReceived(key, units.InHgToHPA(f))
	}
}

func setPlain(o *obs.Observation, key, v string) {
	if f, ok := parseFloat(v); ok {
		o.SetReceived(key, f)
	}
}

func parseFloat(v string) (float64, bool) {
	if v == "" || v == "-9999" {
		return 0, false
	}
	f, err := strconv.ParseFloat(v, 64)
	return f, err == nil
}
