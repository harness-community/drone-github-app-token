// Copyright 2023 the Drone Authors. All rights reserved.
// Use of this source code is governed by the Blue Oak Model License
// that can be found in the LICENSE file.

package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// Args provides plugin execution arguments.
type Args struct {
	Pipeline

	// Level defines the plugin log level.
	Level string `envconfig:"PLUGIN_LOG_LEVEL"`

	// Required inputs
	AppID      string `envconfig:"PLUGIN_APP_ID"`
	PrivateKey string `envconfig:"PLUGIN_PRIVATE_KEY"`

	// Optional inputs
	Owner           string `envconfig:"PLUGIN_OWNER"`
	Repositories    string `envconfig:"PLUGIN_REPOSITORIES"`
	SkipTokenRevoke bool   `envconfig:"PLUGIN_SKIP_TOKEN_REVOKE" default:"false"`
	GitHubAPIURL    string `envconfig:"PLUGIN_GITHUB_API_URL" default:"https://api.github.com"`

	// Permission inputs
	PermissionActions                                           string `envconfig:"PLUGIN_PERMISSION_ACTIONS"`
	PermissionAdministration                                    string `envconfig:"PLUGIN_PERMISSION_ADMINISTRATION"`
	PermissionChecks                                            string `envconfig:"PLUGIN_PERMISSION_CHECKS"`
	PermissionCodespaces                                        string `envconfig:"PLUGIN_PERMISSION_CODESPACES"`
	PermissionContents                                          string `envconfig:"PLUGIN_PERMISSION_CONTENTS"`
	PermissionDependabotSecrets                                 string `envconfig:"PLUGIN_PERMISSION_DEPENDABOT_SECRETS"`
	PermissionDeployments                                       string `envconfig:"PLUGIN_PERMISSION_DEPLOYMENTS"`
	PermissionEmailAddresses                                    string `envconfig:"PLUGIN_PERMISSION_EMAIL_ADDRESSES"`
	PermissionEnvironments                                      string `envconfig:"PLUGIN_PERMISSION_ENVIRONMENTS"`
	PermissionFollowers                                         string `envconfig:"PLUGIN_PERMISSION_FOLLOWERS"`
	PermissionGitSshKeys                                        string `envconfig:"PLUGIN_PERMISSION_GIT_SSH_KEYS"`
	PermissionGpgKeys                                           string `envconfig:"PLUGIN_PERMISSION_GPG_KEYS"`
	PermissionInteractionLimits                                 string `envconfig:"PLUGIN_PERMISSION_INTERACTION_LIMITS"`
	PermissionIssues                                            string `envconfig:"PLUGIN_PERMISSION_ISSUES"`
	PermissionMembers                                           string `envconfig:"PLUGIN_PERMISSION_MEMBERS"`
	PermissionMetadata                                          string `envconfig:"PLUGIN_PERMISSION_METADATA"`
	PermissionOrganizationAdministration                        string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_ADMINISTRATION"`
	PermissionOrganizationAnnouncementBanners                   string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_ANNOUNCEMENT_BANNERS"`
	PermissionOrganizationCopilotSeatManagement                 string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_COPILOT_SEAT_MANAGEMENT"`
	PermissionOrganizationCustomProperties                      string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_CUSTOM_PROPERTIES"`
	PermissionOrganizationEvents                                string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_EVENTS"`
	PermissionOrganizationHooks                                 string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_HOOKS"`
	PermissionOrganizationPackages                              string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_PACKAGES"`
	PermissionOrganizationPersonalAccessTokenRequests           string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_PERSONAL_ACCESS_TOKEN_REQUESTS"`
	PermissionOrganizationPersonalAccessTokenRequestsManagement string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_PERSONAL_ACCESS_TOKEN_REQUESTS_MANAGEMENT"`
	PermissionOrganizationPersonalAccessTokens                  string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_PERSONAL_ACCESS_TOKENS"`
	PermissionOrganizationPlan                                  string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_PLAN"`
	PermissionOrganizationCustomOrgRoles                        string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_CUSTOM_ORG_ROLES"`
	PermissionOrganizationCustomRoles                           string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_CUSTOM_ROLES"`
	PermissionOrganizationProjects                              string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_PROJECTS"`
	PermissionOrganizationSecrets                               string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_SECRETS"`
	PermissionOrganizationSelfHostedRunners                     string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_SELF_HOSTED_RUNNERS"`
	PermissionOrganizationUserBlocking                          string `envconfig:"PLUGIN_PERMISSION_ORGANIZATION_USER_BLOCKING"`
	PermissionPackages                                          string `envconfig:"PLUGIN_PERMISSION_PACKAGES"`
	PermissionPages                                             string `envconfig:"PLUGIN_PERMISSION_PAGES"`
	PermissionProfile                                           string `envconfig:"PLUGIN_PERMISSION_PROFILE"`
	PermissionPullRequests                                      string `envconfig:"PLUGIN_PERMISSION_PULL_REQUESTS"`
	PermissionRepositoryCustomProperties                        string `envconfig:"PLUGIN_PERMISSION_REPOSITORY_CUSTOM_PROPERTIES"`
	PermissionRepositoryHooks                                   string `envconfig:"PLUGIN_PERMISSION_REPOSITORY_HOOKS"`
	PermissionRepositoryProjects                                string `envconfig:"PLUGIN_PERMISSION_REPOSITORY_PROJECTS"`
	PermissionSecretScanningAlerts                              string `envconfig:"PLUGIN_PERMISSION_SECRET_SCANNING_ALERTS"`
	PermissionSecrets                                           string `envconfig:"PLUGIN_PERMISSION_SECRETS"`
	PermissionSecurityEvents                                    string `envconfig:"PLUGIN_PERMISSION_SECURITY_EVENTS"`
	PermissionSingleFile                                        string `envconfig:"PLUGIN_PERMISSION_SINGLE_FILE"`
	PermissionStarring                                          string `envconfig:"PLUGIN_PERMISSION_STARRING"`
	PermissionStatuses                                          string `envconfig:"PLUGIN_PERMISSION_STATUSES"`
	PermissionTeamDiscussions                                   string `envconfig:"PLUGIN_PERMISSION_TEAM_DISCUSSIONS"`
	PermissionVulnerabilityAlerts                               string `envconfig:"PLUGIN_PERMISSION_VULNERABILITY_ALERTS"`
	PermissionWorkflows                                         string `envconfig:"PLUGIN_PERMISSION_WORKFLOWS"`
}

// TokenResponse represents the GitHub App installation token response
type TokenResponse struct {
	Token               string            `json:"token"`
	ExpiresAt           time.Time         `json:"expires_at"`
	Permissions         map[string]string `json:"permissions"`
	RepositorySelection string            `json:"repository_selection"`
}

// InstallationResponse represents the GitHub App installation response
type InstallationResponse struct {
	ID      int64  `json:"id"`
	AppID   int64  `json:"app_id"`
	AppSlug string `json:"app_slug"`
}

// Exec executes the plugin.
func Exec(ctx context.Context, args Args) error {
	if err := validateArgs(args); err != nil {
		return err
	}

	// Determine owner and repositories
	parsedOwner, parsedRepos, err := parseOwnerAndRepos(args)
	if err != nil {
		return err
	}

	// Get permissions map from inputs
	permissions := getPermissionsFromInputs(args)

	// Create JWT for GitHub App authentication
	jwtToken, err := createJWT(args.AppID, args.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create JWT: %w", err)
	}

	// Get installation ID
	var installationID int64
	var appSlug string

	if len(parsedRepos) > 0 {
		// Try to get installation from repository
		installationID, appSlug, err = getRepoInstallation(args.GitHubAPIURL, jwtToken, parsedOwner, parsedRepos[0])
	} else {
		// Get installation for owner
		installationID, appSlug, err = getOwnerInstallation(args.GitHubAPIURL, jwtToken, parsedOwner)
	}

	if err != nil {
		return fmt.Errorf("failed to get installation: %w", err)
	}

	// Create installation token
	token, expiresAt, err := createInstallationToken(args.GitHubAPIURL, jwtToken, installationID, parsedRepos, permissions)
	if err != nil {
		return fmt.Errorf("failed to create installation token: %w", err)
	}

	// Set environment variables - sensitive token goes to secret file
	if err := writeEnvToSecretFile("GITHUB_APP_TOKEN", token); err != nil {
		return err
	}

	// Non-sensitive values go to regular output
	if err := writeEnvToOutputFile("GITHUB_APP_INSTALLATION_ID", fmt.Sprintf("%d", installationID)); err != nil {
		return err
	}

	if err := writeEnvToOutputFile("GITHUB_APP_SLUG", appSlug); err != nil {
		return err
	}

	logrus.Infof("Successfully created GitHub App installation token for '%s'", appSlug)

	// Store token for revocation if needed
	if !args.SkipTokenRevoke {
		if err := os.Setenv("DRONE_GITHUB_APP_TOKEN", token); err != nil {
			return fmt.Errorf("failed to set token environment variable: %w", err)
		}
		if err := os.Setenv("DRONE_GITHUB_APP_TOKEN_EXPIRES_AT", expiresAt.Format(time.RFC3339)); err != nil {
			return fmt.Errorf("failed to set token expiry environment variable: %w", err)
		}

		// Register cleanup function to revoke token
		registerTokenCleanup(args.GitHubAPIURL)
	} else {
		logrus.Info("Token revocation is skipped")
	}

	return nil
}

func validateArgs(args Args) error {
	if args.AppID == "" {
		return fmt.Errorf("app-id is required")
	}

	if args.PrivateKey == "" {
		return fmt.Errorf("private-key is required")
	}

	// Validate permission values
	if err := validatePermissions(args); err != nil {
		return err
	}

	return nil
}

// validatePermissions checks that permission values are valid
func validatePermissions(args Args) error {
	// Get all permission fields using reflection
	v := reflect.ValueOf(args)
	t := v.Type()

	// Define which permissions allow which values
	readWriteOnly := map[string]bool{
		"actions": true, "administration": true, "checks": true,
		"codespaces": true, "contents": true, "dependabot-secrets": true,
		"deployments": true, "email-addresses": true, "environments": true,
		"followers": true, "git-ssh-keys": true, "gpg-keys": true,
		"interaction-limits": true, "issues": true, "members": true,
		"metadata": true, "organization-administration": true,
		"organization-announcement-banners": true, "organization-hooks": true,
		"organization-packages": true, "organization-personal-access-token-requests": true,
		"organization-personal-access-tokens": true, "organization-secrets": true,
		"organization-self-hosted-runners": true, "organization-user-blocking": true,
		"packages": true, "pages": true, "pull-requests": true,
		"repository-custom-properties": true, "repository-hooks": true,
		"secret-scanning-alerts": true, "secrets": true, "security-events": true,
		"single-file": true, "starring": true, "statuses": true,
		"team-discussions": true, "vulnerability-alerts": true,
	}

	readWriteAdminAllowed := map[string]bool{
		"organization-projects": true, "repository-projects": true, "organization-custom-properties": true,
	}

	writeOnly := map[string]bool{
		"profile": true, "workflows": true, "organization-copilot-seat-management": true,
	}

	readOnly := map[string]bool{
		"organization-events": true, "organization-plan": true,
	}

	// Check each permission field
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("envconfig")

		// Only check permission fields
		if strings.HasPrefix(tag, "PLUGIN_PERMISSION_") {
			value := v.Field(i).String()
			if value == "" {
				// Empty permission value is fine (not set)
				continue
			}

			// Get permission name (e.g., "actions" from "PLUGIN_PERMISSION_ACTIONS")
			permName := strings.ToLower(strings.TrimPrefix(tag, "PLUGIN_PERMISSION_"))

			// Check if the value is allowed for this permission
			if readWriteOnly[permName] {
				if value != "read" && value != "write" {
					return fmt.Errorf("permission %s only accepts values 'read' or 'write', got '%s'", permName, value)
				}
			} else if readWriteAdminAllowed[permName] {
				if value != "read" && value != "write" && value != "admin" {
					return fmt.Errorf("permission %s only accepts values 'read', 'write', or 'admin', got '%s'", permName, value)
				}
			} else if writeOnly[permName] {
				if value != "write" {
					return fmt.Errorf("permission %s only accepts value 'write', got '%s'", permName, value)
				}
			} else if readOnly[permName] {
				if value != "read" {
					return fmt.Errorf("permission %s only accepts value 'read', got '%s'", permName, value)
				}
			} else {
				// Default to read/write for permissions we're not explicitly handling
				if value != "read" && value != "write" {
					return fmt.Errorf("permission %s only accepts values 'read' or 'write', got '%s'", permName, value)
				}
			}
		}
	}

	return nil
}

func parseOwnerAndRepos(args Args) (string, []string, error) {
	parsedOwner := args.Owner
	var parsedRepos []string

	if args.Repositories != "" {
		for _, repo := range strings.Split(strings.ReplaceAll(args.Repositories, "\n", ","), ",") {
			if trimmed := strings.TrimSpace(repo); trimmed != "" {
				parsedRepos = append(parsedRepos, trimmed)
			}
		}
	}

	// If neither owner nor repositories are set, default to current repository
	if parsedOwner == "" && len(parsedRepos) == 0 {
		if args.Repo == "" {
			return "", nil, fmt.Errorf("unable to determine repository information")
		}

		parts := strings.Split(args.Repo, "/")
		if len(parts) >= 2 {
			parsedOwner = args.RepoOwner
			parsedRepos = []string{args.RepoName}
			logrus.Infof("Using current repository: %s/%s from pipeline context", parsedOwner, parsedRepos[0])
		} else {
			return "", nil, fmt.Errorf("invalid repository format: %s", args.Repo)
		}
	}

	// If only owner is set
	if parsedOwner != "" && len(parsedRepos) == 0 {
		logrus.Infof("Creating token for all repositories under Organization: %s", parsedOwner)
	}

	// If repositories are set but no owner
	if parsedOwner == "" && len(parsedRepos) > 0 {
		parsedOwner = args.RepoOwner
		logrus.Infof("Using current Organization: '%s' for Repositories: %s", parsedOwner, strings.Join(parsedRepos, ", "))
	}

	// Both owner and repositories are set
	if parsedOwner != "" && len(parsedRepos) > 0 {
		logrus.Infof("Creating token for Repositories: %s under Organization: %s", strings.Join(parsedRepos, ", "), parsedOwner)
	}

	return parsedOwner, parsedRepos, nil
}

// getPermissionsFromInputs extracts permissions from Args into a map
func getPermissionsFromInputs(args Args) map[string]string {
	perms := make(map[string]string)

	// Use reflection to iterate through the struct fields
	v := reflect.ValueOf(args)
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("envconfig")

		if strings.HasPrefix(tag, "PLUGIN_PERMISSION_") {
			value := v.Field(i).String()
			if value != "" {
				permName := strings.ToLower(strings.TrimPrefix(tag, "PLUGIN_PERMISSION_"))
				perms[permName] = value
			}
		}
	}

	return perms
}

// createJWT creates a JWT token for authenticating as a GitHub App
func createJWT(appID, privateKey string) (string, error) {
	// Parse PEM encoded private key
	privateKey = strings.ReplaceAll(privateKey, "\\n", "\n")

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privateKey))
	if err != nil {
		return "", fmt.Errorf("could not parse private key: %w", err)
	}

	// Create a new token
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": now.Unix(),                       // Issued at time
		"exp": now.Add(10 * time.Minute).Unix(), // Expires in 10 minutes
		"iss": appID,                            // Issuer is the app ID
	})

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("could not sign token: %w", err)
	}

	return tokenString, nil
}

// getOwnerInstallation gets the installation ID for an owner (org or user)
func getOwnerInstallation(baseURL, jwtToken, owner string) (int64, string, error) {
	url := fmt.Sprintf("%s/users/%s/installation", baseURL, owner)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var installation InstallationResponse
	if err := json.NewDecoder(resp.Body).Decode(&installation); err != nil {
		return 0, "", fmt.Errorf("failed to decode response: %w", err)
	}

	return installation.ID, installation.AppSlug, nil
}

// getRepoInstallation gets the installation ID for a repository
func getRepoInstallation(baseURL, jwtToken, owner, repo string) (int64, string, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/installation", baseURL, owner, repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return 0, "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var installation InstallationResponse
	if err := json.NewDecoder(resp.Body).Decode(&installation); err != nil {
		return 0, "", fmt.Errorf("failed to decode response: %w", err)
	}

	return installation.ID, installation.AppSlug, nil
}

// createInstallationToken creates an installation token
func createInstallationToken(baseURL, jwtToken string, installationID int64, repositories []string, permissions map[string]string) (string, time.Time, error) {
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", baseURL, installationID)

	payload := map[string]interface{}{
		"permissions": permissions,
	}

	if len(repositories) > 0 {
		payload["repositories"] = repositories
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return tokenResp.Token, tokenResp.ExpiresAt, nil
}

// writeEnvToSecretFile writes sensitive environment variables to the Harness secret output file
func writeEnvToSecretFile(key, value string) error {
	outputFile, err := os.OpenFile(os.Getenv("HARNESS_OUTPUT_SECRET_FILE"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open secret output file: %w", err)
	}

	defer outputFile.Close()

	_, err = fmt.Fprintf(outputFile, "%s=%s\n", key, value)
	if err != nil {
		return fmt.Errorf("failed to write to secret env: %w", err)
	}

	return nil
}

// writeEnvToOutputFile writes non-sensitive environment variables to the regular Harness output file
func writeEnvToOutputFile(key, value string) error {
	outputFile, err := os.OpenFile(os.Getenv("DRONE_OUTPUT"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}

	defer outputFile.Close()

	_, err = fmt.Fprintf(outputFile, "%s=%s\n", key, value)
	if err != nil {
		return fmt.Errorf("failed to write to env: %w", err)
	}

	return nil
}

// registerTokenCleanup registers a function to revoke the token when the program exits
func registerTokenCleanup(baseURL string) {
	// Using a goroutine to handle cleanup
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		revokeToken(baseURL)
		os.Exit(0)
	}()
}

// revokeToken revokes the GitHub App installation token
func revokeToken(baseURL string) {
	token := os.Getenv("DRONE_GITHUB_APP_TOKEN")
	if token == "" {
		logrus.Info("Token is not set")
		return
	}

	expiresAtStr := os.Getenv("DRONE_GITHUB_APP_TOKEN_EXPIRES_AT")
	if expiresAtStr != "" {
		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err == nil && time.Now().After(expiresAt) {
			logrus.Info("Token expired, skipping token revocation")
			return
		}
	}

	url := fmt.Sprintf("%s/installation/token", baseURL)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		logrus.WithError(err).Warning("Failed to create revocation request")
		return
	}

	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logrus.WithError(err).Warning("Token revocation request failed")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		logrus.Info("Token revoked successfully")
	} else {
		body, _ := io.ReadAll(resp.Body)
		logrus.Warningf("Token revocation failed: status=%d, body=%s", resp.StatusCode, string(body))
	}
}
