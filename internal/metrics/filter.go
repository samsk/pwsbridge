package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// StationGatherer exposes only weather series for one tenant and station.
type StationGatherer struct {
	Inner   prometheus.Gatherer
	Tenant  string
	Station string
}

// Gather returns metric families filtered to Tenant and Station labels.
func (g StationGatherer) Gather() ([]*dto.MetricFamily, error) {
	fams, err := g.Inner.Gather()
	if err != nil {
		return nil, err
	}
	out := make([]*dto.MetricFamily, 0, len(fams))
	for _, f := range fams {
		kept := make([]*dto.Metric, 0, len(f.Metric))
		for _, m := range f.Metric {
			if labelValue(m, "station") != g.Station {
				continue
			}
			if g.Tenant != "" && labelValue(m, "tenant") != g.Tenant {
				continue
			}
			kept = append(kept, m)
		}
		if len(kept) == 0 {
			continue
		}
		copyFam := *f
		copyFam.Metric = kept
		out = append(out, &copyFam)
	}
	return out, nil
}

func labelValue(m *dto.Metric, name string) string {
	for _, l := range m.Label {
		if l.GetName() == name {
			return l.GetValue()
		}
	}
	return ""
}
