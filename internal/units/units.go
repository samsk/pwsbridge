package units

// FToC converts Fahrenheit to Celsius.
func FToC(f float64) float64 {
	return (f - 32) * 5 / 9
}

// InchesToMM converts inches to millimeters.
func InchesToMM(inches float64) float64 {
	return inches * 25.4
}

// MPHToKPH converts miles per hour to kilometers per hour.
func MPHToKPH(mph float64) float64 {
	return mph * 1.609344
}

// InHgToHPA converts inches of mercury to hectopascals.
func InHgToHPA(inHg float64) float64 {
	return inHg * 33.8639
}

// KPHToMPS converts kilometers per hour to meters per second.
func KPHToMPS(kph float64) float64 {
	return kph / 3.6
}
