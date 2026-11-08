package calc

import (
	"errors"
	"math"

	"github.com/samsk/pwsbridge/internal/units"
)

// AbsoluteHumidity returns g/m³ for tempC and relative humidity 0-1.
func AbsoluteHumidity(tempC, relHumidity float64) (float64, error) {
	if tempC < -273.15 {
		return 0, errors.New("temp cannot be below absolute zero")
	}
	if relHumidity < 0 || relHumidity > 1 {
		return 0, errors.New("relative humidity must be between 0.0 and 1.0")
	}
	es := 6.112 * math.Exp((17.67*tempC)/(tempC+243.5))
	ea := relHumidity * es
	return (ea * 216.7) / (tempC + 273.15), nil
}

// DewPoint calculates dew point °C using Magnus-Tetens.
func DewPoint(tempC, relHumidity float64) (float64, error) {
	if relHumidity <= 0 || relHumidity > 1 {
		return 0, errors.New("relative humidity must be between 0.0 and 1.0")
	}
	alpha := math.Log(relHumidity) + (17.625*tempC)/(243.04+tempC)
	return (243.04 * alpha) / (17.625 - alpha), nil
}

// FeelsLike returns NOAA apparent temperature °C.
func FeelsLike(tempC, relHumidity, windSpeedKPH float64) (float64, error) {
	if tempC >= 26.7 {
		return HeatIndex(tempC, relHumidity)
	}
	if tempC <= 10 && units.KPHToMPS(windSpeedKPH) >= 1.34 {
		return WindChill(tempC, windSpeedKPH)
	}
	return tempC, nil
}

// ApparentTemperatureAU returns Australian BoM apparent temperature °C.
func ApparentTemperatureAU(tempC, relHumidity, windSpeedKPH, solarRadiation float64) (float64, error) {
	if relHumidity < 0 || relHumidity > 1 {
		return 0, errors.New("relative humidity must be between 0.0 and 1.0")
	}
	e := relHumidity * 6.105 * math.Exp((17.27*tempC)/(237.7+tempC))
	windMS := units.KPHToMPS(windSpeedKPH)
	return tempC + 0.348*e - 0.70*windMS + 0.70*(solarRadiation/(windMS+10)) - 4.25, nil
}

// HeatIndex returns NOAA heat index °C.
func HeatIndex(tempC, relHumidity float64) (float64, error) {
	if relHumidity < 0 || relHumidity > 1 {
		return 0, errors.New("relative humidity must be between 0.0 and 1.0")
	}
	tF := tempC*9/5 + 32
	rh := relHumidity * 100
	if tF < 80 {
		return tempC, nil
	}
	hi := -42.379 + 2.04901523*tF + 10.14333127*rh -
		0.22475541*tF*rh - 0.00683783*tF*tF - 0.05481717*rh*rh +
		0.00122874*tF*tF*rh + 0.00085282*tF*rh*rh - 0.00000199*tF*tF*rh*rh
	if rh < 13 && tF >= 80 && tF <= 112 {
		hi -= ((13 - rh) / 4) * math.Sqrt((17-math.Abs(tF-95))/17)
	}
	if rh > 85 && tF >= 80 && tF <= 87 {
		hi += ((rh - 85) / 10) * ((87 - tF) / 5)
	}
	return (hi - 32) * 5 / 9, nil
}

// WindChill returns NOAA wind chill °C for wind speed in km/h.
func WindChill(tempC, windSpeedKPH float64) (float64, error) {
	windMPH := windSpeedKPH * 0.621371
	tempF := tempC*9/5 + 32
	if tempF > 50 || windMPH < 3 {
		return tempC, nil
	}
	wc := 35.74 + 0.6215*tempF - 35.75*math.Pow(windMPH, 0.16) +
		0.4275*tempF*math.Pow(windMPH, 0.16)
	return (wc - 32) * 5 / 9, nil
}
