package term

import "testing"

func TestParseMode(t *testing.T) {
	cases := map[string]Mode{"": Auto, "auto": Auto, "ALWAYS": Always, "never": Never, "off": Never}
	for in, want := range cases {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseMode("sometimes"); err == nil {
		t.Error("ParseMode accepted an invalid value")
	}
}

func TestModeOverrides(t *testing.T) {
	t.Cleanup(func() { SetMode(Auto) })

	SetMode(Never)
	if C(Red) != "" || Paint(Red, "x") != "x" {
		t.Error("color emitted with mode Never")
	}
	SetMode(Always)
	if C(Red) != Red || Paint(Red, "x") != Red+"x"+Reset {
		t.Error("color missing with mode Always")
	}
}
