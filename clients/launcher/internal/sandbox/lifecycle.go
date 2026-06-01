// Package sandbox manages opt-in per-engagement sandbox containers and
// engagement-scoped Neo4j credentials.
package sandbox

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/PurpleAILAB/Decepticon/clients/launcher/internal/compose"
	"github.com/PurpleAILAB/Decepticon/clients/launcher/internal/config"
)

const (
	defaultMemory = "4g"
	defaultPids   = "4096"
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$`)

// Manager owns lifecycle operations for per-engagement sandboxes.
type Manager struct {
	Compose *compose.Compose
	Env     map[string]string
}

// Credentials are the rotated Bolt credentials for one engagement.
type Credentials struct {
	Username string
	Password string
	Path     string
}

// ContainerName returns the deterministic sandbox container name.
func ContainerName(slug string) string {
	return compose.ContainerName("sandbox-" + slug)
}

// SandboxURL returns the URL LangGraph should use for an engagement sandbox.
func SandboxURL(slug string) string {
	return "http://" + ContainerName(slug) + ":9999"
}

// Enabled reports whether per-engagement sandbox isolation is enabled.
func Enabled(env map[string]string) bool {
	v := strings.ToLower(strings.TrimSpace(config.Get(env, "DECEPTICON_SANDBOX_PER_ENGAGEMENT", "")))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

// NewManager creates a lifecycle manager.
func NewManager(c *compose.Compose, env map[string]string) *Manager {
	return &Manager{Compose: c, Env: env}
}

// Ensure starts or replaces the engagement sandbox and rotates its Neo4j user.
func (m *Manager) Ensure(slug, workspace string) (Credentials, string, error) {
	if err := validateSlug(slug); err != nil {
		return Credentials{}, "", err
	}
	if workspace == "" {
		return Credentials{}, "", fmt.Errorf("workspace path is required")
	}
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return Credentials{}, "", fmt.Errorf("create workspace: %w", err)
	}
	creds, err := m.RotateCypherUser(slug, workspace)
	if err != nil {
		return Credentials{}, "", err
	}
	if err := m.StartContainer(slug, workspace, creds); err != nil {
		return Credentials{}, "", err
	}
	return creds, SandboxURL(slug), nil
}

// Stop removes the engagement sandbox container if it exists.
func (m *Manager) Stop(slug string) error {
	if err := validateSlug(slug); err != nil {
		return err
	}
	return m.runRuntime("rm", "-f", ContainerName(slug))
}

// List prints matching engagement sandbox containers.
func (m *Manager) List() error {
	return m.runRuntime(
		"ps",
		"--filter", "name="+compose.ContainerName("sandbox-"),
		"--format", "table {{.Names}}\t{{.Status}}\t{{.Image}}",
	)
}

// RotateCypherUser rotates the per-engagement Neo4j password and persists it
// under the engagement workspace with 0600 permissions.
func (m *Manager) RotateCypherUser(slug, workspace string) (Credentials, error) {
	if err := validateSlug(slug); err != nil {
		return Credentials{}, err
	}
	password, err := randomSecret(32)
	if err != nil {
		return Credentials{}, err
	}
	username := CypherUsername(slug)
	adminPassword := config.Get(m.Env, "NEO4J_PASSWORD", "decepticon-graph")
	query := fmt.Sprintf(
		"DROP USER %s IF EXISTS; CREATE USER %s SET PASSWORD '%s' CHANGE NOT REQUIRED;",
		username,
		username,
		escapeCypherString(password),
	)
	if err := m.runRuntime("exec", compose.ContainerName("neo4j"), "cypher-shell", "-u", "neo4j", "-p", adminPassword, query); err != nil {
		return Credentials{}, fmt.Errorf("rotate cypher user: %w", err)
	}

	secretDir := filepath.Join(workspace, ".secrets")
	if err := os.MkdirAll(secretDir, 0o700); err != nil {
		return Credentials{}, fmt.Errorf("create secret dir: %w", err)
	}
	path := filepath.Join(secretDir, "cypher.env")
	body := "NEO4J_URI=bolt://neo4j:7687\n" +
		"NEO4J_USER=" + username + "\n" +
		"NEO4J_PASSWORD=" + password + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return Credentials{}, fmt.Errorf("write cypher secret: %w", err)
	}
	return Credentials{Username: username, Password: password, Path: path}, nil
}

// StartContainer replaces the engagement sandbox container and waits for its
// FastAPI daemon to answer inside the container namespace.
func (m *Manager) StartContainer(slug, workspace string, creds Credentials) error {
	if err := validateSlug(slug); err != nil {
		return err
	}
	name := ContainerName(slug)
	_ = m.runRuntimeQuiet("rm", "-f", name)

	args := []string{
		"run", "-d",
		"--name", name,
		"--network", composeNetwork("sandbox-net"),
		"--init",
		"--cap-drop", "ALL",
		"--cap-add", "NET_RAW",
		"--cap-add", "NET_ADMIN",
		"--cap-add", "NET_BIND_SERVICE",
		"--cap-add", "SYS_PTRACE",
		"--cap-add", "SETUID",
		"--cap-add", "SETGID",
		"--cap-add", "CHOWN",
		"--cap-add", "DAC_OVERRIDE",
		"--cap-add", "FOWNER",
		"--cap-add", "KILL",
		"--security-opt", "no-new-privileges:true",
		"--memory", config.Get(m.Env, "DECEPTICON_SANDBOX_PER_ENG_MEMORY", defaultMemory),
		"--pids-limit", config.Get(m.Env, "DECEPTICON_SANDBOX_PER_ENG_PIDS", defaultPids),
		"-e", "SANDBOX_DAEMON=1",
		"-e", "DECEPTICON_ENGAGEMENT=" + slug,
		"-e", "NEO4J_URI=bolt://neo4j:7687",
		"-e", "NEO4J_USER=" + creds.Username,
		"-e", "NEO4J_PASSWORD=" + creds.Password,
		"-v", workspace + ":/workspace",
		sandboxImage(m.Env),
	}
	if cpus := strings.TrimSpace(config.Get(m.Env, "DECEPTICON_SANDBOX_PER_ENG_CPUS", "")); cpus != "" {
		args = append(args[:len(args)-1], "--cpus", cpus, args[len(args)-1])
	}
	if err := m.runRuntime(args...); err != nil {
		return fmt.Errorf("start sandbox container: %w", err)
	}
	if err := m.waitForDaemon(name); err != nil {
		return err
	}
	return restoreSecretPermissions(creds.Path)
}

func (m *Manager) waitForDaemon(name string) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		err := m.runRuntimeQuiet(
			"exec", name,
			"python3", "-c",
			"import urllib.request; urllib.request.urlopen('http://127.0.0.1:9999/healthz', timeout=2)",
		)
		if err == nil {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("sandbox daemon did not become healthy: %s", name)
}

func (m *Manager) runRuntime(args ...string) error {
	cmd := exec.Command(m.Compose.Runtime.Bin, args...)
	cmd.Env = m.Compose.Runtime.Apply(os.Environ())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (m *Manager) runRuntimeQuiet(args ...string) error {
	cmd := exec.Command(m.Compose.Runtime.Bin, args...)
	cmd.Env = m.Compose.Runtime.Apply(os.Environ())
	return cmd.Run()
}

// CypherUsername returns the safe Neo4j username for an engagement.
func CypherUsername(slug string) string {
	safe := strings.ReplaceAll(slug, "-", "_")
	if len(safe) > 48 {
		safe = safe[:48]
	}
	return "decepticon_" + safe
}

func validateSlug(slug string) error {
	if !slugRe.MatchString(slug) {
		return fmt.Errorf("invalid engagement slug %q", slug)
	}
	return nil
}

func randomSecret(bytes int) (string, error) {
	buf := make([]byte, bytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("random secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func escapeCypherString(s string) string {
	return strings.ReplaceAll(s, "'", "\\'")
}

func composeNetwork(serviceNetwork string) string {
	stack := strings.TrimSpace(os.Getenv("DECEPTICON_STACK_NAME"))
	if stack == "" {
		return "decepticon_" + serviceNetwork
	}
	return "decepticon-" + stack + "_" + serviceNetwork
}

func sandboxImage(env map[string]string) string {
	if image := strings.TrimSpace(config.Get(env, "DECEPTICON_SANDBOX_IMAGE", "")); image != "" {
		return image
	}
	version := strings.TrimSpace(os.Getenv("DECEPTICON_VERSION"))
	if version == "" {
		version = strings.TrimSpace(config.Get(env, "DECEPTICON_VERSION", "latest"))
	}
	if version == "" {
		version = "latest"
	}
	version = strings.TrimPrefix(version, "v")
	return "ghcr.io/purpleailab/decepticon-sandbox:" + version
}

func restoreSecretPermissions(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("restore secret dir permissions: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restore secret file permissions: %w", err)
	}
	return nil
}

// ProbeURL validates the external sandbox URL. Used by tests and future status
// commands; kept here so URL semantics stay close to lifecycle generation.
func ProbeURL(url string) bool {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(strings.TrimRight(url, "/") + "/healthz")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 400
}
