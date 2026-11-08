package calc

import "github.com/samsk/pwsbridge/internal/obs"

// Apply fills missing derived fields on obs when enabled.
func Apply(o *obs.Observation) {
	temp, hasTemp := o.Get("temperature")
	hum, hasHum := o.Get("humidity")
	wind, _ := o.Get("wind_speed")
	solar, _ := o.Get("solar_radiation")

	var rel float64
	if hasHum {
		rel = hum / 100
	}

	if hasTemp && hasHum && !o.WasReceived("humidity_abs") {
		if v, err := AbsoluteHumidity(temp, rel); err == nil {
			o.SetDerived("humidity_abs", v)
		}
	}
	if hasTemp && hasHum && !o.WasReceived("dew_point") {
		if v, err := DewPoint(temp, rel); err == nil {
			o.SetDerived("dew_point", v)
		}
	}
	if hasTemp && hasHum && !o.WasReceived("heat_index") {
		if v, err := HeatIndex(temp, rel); err == nil {
			o.SetDerived("heat_index", v)
		}
	}
	if hasTemp && !o.WasReceived("wind_chill") {
		if v, err := WindChill(temp, wind); err == nil {
			o.SetDerived("wind_chill", v)
		}
	}
	if hasTemp && hasHum && !o.WasReceived("feels_like") {
		if v, err := FeelsLike(temp, rel, wind); err == nil {
			o.SetDerived("feels_like", v)
		}
	}
	if hasTemp && hasHum && !o.WasReceived("aus_apparent_temp") {
		if v, err := ApparentTemperatureAU(temp, rel, wind, solar); err == nil {
			o.SetDerived("aus_apparent_temp", v)
		}
	}
}
