package skyforge

import "testing"

func TestSanitizeCoderLaunchPath(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: "/coder/"},
		{name: "trimmed", in: " /coder/users ", want: "/coder/users"},
		{name: "no leading slash", in: "coder/users", want: "/coder/users"},
		{name: "invalid prefix", in: "/dashboard", want: "/coder/"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeCoderLaunchPath(tc.in); got != tc.want {
				t.Fatalf("sanitizeCoderLaunchPath(%q)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}
