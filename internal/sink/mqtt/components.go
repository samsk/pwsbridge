package mqtt

// Component is one HA MQTT discovery sensor definition.
type Component struct {
	ID          string
	Name        string
	DeviceClass string
	StateClass  string
	Unit        string
	Icon        string
}

var knownComponents = []Component{
	{ID: "temperature", Name: "Temperature", DeviceClass: "temperature", StateClass: "measurement", Unit: "°C"},
	{ID: "humidity", Name: "Humidity", DeviceClass: "humidity", StateClass: "measurement", Unit: "%"},
	{ID: "dew_point", Name: "Dew Point", DeviceClass: "temperature", StateClass: "measurement", Unit: "°C"},
	{ID: "humidity_abs", Name: "Absolute Humidity", StateClass: "measurement", Unit: "g/m³", Icon: "mdi:water-percent"},
	{ID: "indoor_temperature", Name: "Indoor Temperature", DeviceClass: "temperature", StateClass: "measurement", Unit: "°C"},
	{ID: "indoor_humidity", Name: "Indoor Humidity", DeviceClass: "humidity", StateClass: "measurement", Unit: "%"},
	{ID: "wind_speed", Name: "Wind Speed", DeviceClass: "wind_speed", StateClass: "measurement", Unit: "km/h"},
	{ID: "wind_gust", Name: "Wind Gust", DeviceClass: "wind_speed", StateClass: "measurement", Unit: "km/h"},
	{ID: "wind_direction", Name: "Wind Direction", DeviceClass: "wind_direction", StateClass: "measurement_angle", Unit: "°"},
	{ID: "rain_past_hour", Name: "Hourly Rain", DeviceClass: "precipitation", StateClass: "measurement", Unit: "mm"},
	{ID: "rain_daily", Name: "Daily Rain", DeviceClass: "precipitation", StateClass: "total_increasing", Unit: "mm"},
	{ID: "rain_weekly", Name: "Weekly Rain", DeviceClass: "precipitation", StateClass: "total_increasing", Unit: "mm"},
	{ID: "rain_monthly", Name: "Monthly Rain", DeviceClass: "precipitation", StateClass: "total_increasing", Unit: "mm"},
	{ID: "rain_yearly", Name: "Yearly Rain", DeviceClass: "precipitation", StateClass: "total_increasing", Unit: "mm"},
	{ID: "pressure", Name: "Pressure", DeviceClass: "atmospheric_pressure", StateClass: "measurement", Unit: "hPa"},
	{ID: "pressure_abs", Name: "Absolute Pressure", DeviceClass: "atmospheric_pressure", StateClass: "measurement", Unit: "hPa"},
	{ID: "solar_radiation", Name: "Solar Radiation", DeviceClass: "irradiance", StateClass: "measurement", Unit: "W/m²"},
	{ID: "uv_index", Name: "UV Index", StateClass: "measurement", Unit: "UV index", Icon: "mdi:sun-wireless"},
	{ID: "wind_chill", Name: "Wind Chill", DeviceClass: "temperature", StateClass: "measurement", Unit: "°C"},
	{ID: "heat_index", Name: "Heat Index", DeviceClass: "temperature", StateClass: "measurement", Unit: "°C"},
	{ID: "feels_like", Name: "Feels Like", DeviceClass: "temperature", StateClass: "measurement", Unit: "°C"},
	{ID: "aus_apparent_temp", Name: "Apparent Temperature (AUS)", DeviceClass: "temperature", StateClass: "measurement", Unit: "°C"},
	{ID: "pm25", Name: "PM2.5", DeviceClass: "pm25", StateClass: "measurement", Unit: "μg/m³"},
	{ID: "pm10", Name: "PM10", DeviceClass: "pm10", StateClass: "measurement", Unit: "μg/m³"},
}

func componentFor(field string) Component {
	for _, c := range knownComponents {
		if c.ID == field {
			return c
		}
	}
	return Component{ID: field, Name: field, StateClass: "measurement", Icon: "mdi:weather-cloudy"}
}
