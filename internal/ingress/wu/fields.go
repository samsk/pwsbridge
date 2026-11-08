package wu

import (
	"strconv"

	"github.com/samsk/pwsbridge/internal/obs"
	"github.com/samsk/pwsbridge/internal/units"
)

// SubmissionPath is the WU PWS upload path.
const SubmissionPath = "/weatherstation/updateweatherstation.php"

var metadata = map[string]struct{}{
	"ID": {}, "PASSWORD": {}, "action": {}, "dateutc": {},
	"realtime": {}, "rtfreq": {}, "softwaretype": {},
}

type mapper func(string, *obs.Observation)

var fieldMap = map[string]mapper{
	"tempf":          mapTemp("temperature"),
	"humidity":       mapPlain("humidity"),
	"dewptf":         mapTemp("dew_point"),
	"indoortempf":    mapTemp("indoor_temperature"),
	"indoorhumidity": mapPlain("indoor_humidity"),
	"temp2f":         mapTemp("temperature_2"),
	"temp3f":         mapTemp("temperature_3"),
	"temp4f":         mapTemp("temperature_4"),
	"temp5f":         mapTemp("temperature_5"),
	"temp6f":         mapTemp("temperature_6"),
	"temp7f":         mapTemp("temperature_7"),
	"temp8f":         mapTemp("temperature_8"),
	"temp9f":         mapTemp("temperature_9"),
	"temp10f":        mapTemp("temperature_10"),
	"windchillf":     mapTemp("wind_chill"),
	"heatindexf":     mapTemp("heat_index"),
	"feelslikef":     mapTemp("feels_like"),
	"windspeedmph":   mapSpeed("wind_speed"),
	"winddir":        mapPlain("wind_direction"),
	"windgustmph":    mapSpeed("wind_gust"),
	"windgustdir":    mapPlain("wind_gust_direction"),
	"windspdmph_avg2m": mapSpeed("wind_speed_avg_2m"),
	"winddir_avg2m":    mapPlain("wind_direction_avg_2m"),
	"windgustmph_10m":  mapSpeed("wind_gust_10m"),
	"windgustdir_10m":  mapPlain("wind_gust_direction_10m"),
	"rainin":         mapRain("rain_past_hour"),
	"dailyrainin":    mapRain("rain_daily"),
	"weeklyrainin":   mapRain("rain_weekly"),
	"monthlyrainin":  mapRain("rain_monthly"),
	"yearlyrainin":   mapRain("rain_yearly"),
	"baromin":        mapPressure("pressure"),
	"absbaromin":     mapPressure("pressure_abs"),
	"solarradiation": mapPlain("solar_radiation"),
	"UV":             mapPlain("uv_index"),
	"soiltempf":      mapTemp("soil_temperature"),
	"soiltemp2f":     mapTemp("soil_temperature_2"),
	"soiltemp3f":     mapTemp("soil_temperature_3"),
	"soiltemp4f":     mapTemp("soil_temperature_4"),
	"soilmoisture":   mapPlain("soil_moisture"),
	"soilmoisture2":  mapPlain("soil_moisture_2"),
	"soilmoisture3":  mapPlain("soil_moisture_3"),
	"soilmoisture4":  mapPlain("soil_moisture_4"),
	"leafwetness":    mapPlain("leaf_wetness"),
	"leafwetness2":   mapPlain("leaf_wetness_2"),
	"AqPM2.5":        mapPlain("pm25"),
	"AqPM10":         mapPlain("pm10"),
}

func mapTemp(key string) mapper {
	return func(v string, o *obs.Observation) {
		if f, ok := parseFloat(v); ok {
			o.SetReceived(key, units.FToC(f))
		}
	}
}

func mapSpeed(key string) mapper {
	return func(v string, o *obs.Observation) {
		if f, ok := parseFloat(v); ok {
			o.SetReceived(key, units.MPHToKPH(f))
		}
	}
}

func mapRain(key string) mapper {
	return func(v string, o *obs.Observation) {
		if f, ok := parseFloat(v); ok {
			o.SetReceived(key, units.InchesToMM(f))
		}
	}
}

func mapPressure(key string) mapper {
	return func(v string, o *obs.Observation) {
		if f, ok := parseFloat(v); ok {
			o.SetReceived(key, units.InHgToHPA(f))
		}
	}
}

func mapPlain(key string) mapper {
	return func(v string, o *obs.Observation) {
		if f, ok := parseFloat(v); ok {
			o.SetReceived(key, f)
		}
	}
}

func parseFloat(v string) (float64, bool) {
	if v == "" || v == "-9999" {
		return 0, false
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// ApplyParams maps WU query/form params onto an observation.
func ApplyParams(params map[string]string, o *obs.Observation) {
	for k, v := range params {
		if _, skip := metadata[k]; skip {
			continue
		}
		if fn, ok := fieldMap[k]; ok {
			fn(v, o)
			continue
		}
		if !obs.ValidKey(k) {
			continue
		}
		if f, ok := parseFloat(v); ok {
			o.SetReceived(k, f)
		}
	}
}
