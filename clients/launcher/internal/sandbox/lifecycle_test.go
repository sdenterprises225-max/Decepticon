package sandbox

import "testing"

func TestCypherUsernameSanitizesSlug(t *testing.T) {
	got := CypherUsername("acme-external-2026")
	want := "decepticon_acme_external_2026"
	if got != want {
		t.Fatalf("CypherUsername = %q, want %q", got, want)
	}
}

func TestContainerNameUsesEngagementSuffix(t *testing.T) {
	t.Setenv("DECEPTICON_STACK_NAME", "")
	got := ContainerName("acme-external-2026")
	want := "decepticon-sandbox-acme-external-2026"
	if got != want {
		t.Fatalf("ContainerName = %q, want %q", got, want)
	}
}

func TestContainerNameHonorsStackName(t *testing.T) {
	t.Setenv("DECEPTICON_STACK_NAME", "red")
	got := ContainerName("acme")
	want := "decepticon-red-sandbox-acme"
	if got != want {
		t.Fatalf("ContainerName = %q, want %q", got, want)
	}
}

func TestSandboxURLOwesContainerDNSName(t *testing.T) {
	t.Setenv("DECEPTICON_STACK_NAME", "")
	got := SandboxURL("acme")
	want := "http://decepticon-sandbox-acme:9999"
	if got != want {
		t.Fatalf("SandboxURL = %q, want %q", got, want)
	}
}

func TestEnabledAcceptsTruthyValues(t *testing.T) {
	for _, val := range []string{"1", "true", "yes", "on"} {
		if !Enabled(map[string]string{"DECEPTICON_SANDBOX_PER_ENGAGEMENT": val}) {
			t.Fatalf("Enabled(%q) = false, want true", val)
		}
	}
	if Enabled(map[string]string{"DECEPTICON_SANDBOX_PER_ENGAGEMENT": "false"}) {
		t.Fatal("Enabled(false) = true, want false")
	}
}
