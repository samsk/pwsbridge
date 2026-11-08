package units

import "testing"

func TestFToC(t *testing.T) {
	if got := FToC(63.5); got != 17.5 {
		t.Fatalf("FToC(63.5)=%v want 17.5", got)
	}
}

func TestFactors(t *testing.T) {
	if got := InchesToMM(1); got != 25.4 {
		t.Fatalf("InchesToMM=%v", got)
	}
	if got := MPHToKPH(1); got != 1.609344 {
		t.Fatalf("MPHToKPH=%v", got)
	}
	if got := InHgToHPA(1); got != 33.8639 {
		t.Fatalf("InHgToHPA=%v", got)
	}
}
