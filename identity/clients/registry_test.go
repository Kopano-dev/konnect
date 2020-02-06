package clients

import "testing"

func TestRedirectUriWithDynamicPort(t *testing.T) {
	redirectURIs := []struct {
		uri       string
		shallFail bool
	}{
		{"http://localhost:12345", false},
		{"http://localhost:12345/callback", false},
		{"http://localhost", false},
		{"custom://callback.example.net", false},
		{"http://localhost:12345/callback-disallowed", true},
		{"http://localhost.example.net/callback", true},
		{"http://host-with-port:1234/callback", false},
		{"http://host-with-port:123/callback", true},
	}

	registry, _ := NewRegistry(nil, nil, "", nil)
	clientRegistration := ClientRegistration{
		ID:              "native",
		Secret:          "secret",
		Trusted:         true,
		TrustedScopes:   nil,
		Insecure:        false,
		Dynamic:         false,
		ApplicationType: "native",
		RedirectURIs:    []string{"http://localhost", "http://localhost/callback", "custom://callback.example.net", "http://host-with-port:1234/callback"},
	}
	for _, redirectURI := range redirectURIs {
		err := registry.Validate(&clientRegistration, "secret", redirectURI.uri, "", false)
		if !redirectURI.shallFail && err != nil {
			t.Errorf("Native client with dynamic port for redirectURI '%v' failed: %v", redirectURI.uri, err)
		}
		if redirectURI.shallFail && err == nil {
			t.Errorf("Native client with dynamic port for redirectURI '%v' did not fail as expected.", redirectURI.uri)
		}
	}
}
