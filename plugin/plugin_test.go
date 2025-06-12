package plugin

import (
	"os"
	"testing"
)

func TestValidateArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    Args
		wantErr bool
	}{
		{
			name:    "Empty args",
			args:    Args{},
			wantErr: true,
		},
		{
			name: "Only App ID",
			args: Args{
				AppID: "12345",
			},
			wantErr: true,
		},
		{
			name: "Only Private Key",
			args: Args{
				PrivateKey: "private-key-content",
			},
			wantErr: true,
		},
		{
			name: "Valid required args",
			args: Args{
				AppID:      "12345",
				PrivateKey: "private-key-content",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateArgs(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateArgs() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseOwnerAndRepos(t *testing.T) {
	// Set up test environment variables to simulate Drone environment
	os.Setenv("DRONE_REPO", "test-owner/test-repo")
	os.Setenv("DRONE_REPO_OWNER", "test-owner")
	os.Setenv("DRONE_REPO_NAME", "test-repo")

	defer func() {
		os.Unsetenv("DRONE_REPO")
		os.Unsetenv("DRONE_REPO_OWNER")
		os.Unsetenv("DRONE_REPO_NAME")
	}()

	tests := []struct {
		name         string
		args         Args
		wantOwner    string
		wantReposLen int
		wantErr      bool
	}{
		{
			name: "No owner or repositories",
			args: Args{
				Pipeline: Pipeline{
					Repo:      "test-owner/test-repo",
					RepoOwner: "test-owner",
					RepoName:  "test-repo",
				},
				Owner:        "",
				Repositories: "",
			},
			wantOwner:    "test-owner",
			wantReposLen: 1,
			wantErr:      false,
		},
		{
			name: "With owner, no repositories",
			args: Args{
				Pipeline: Pipeline{
					Repo:      "test-owner/test-repo",
					RepoOwner: "test-owner",
					RepoName:  "test-repo",
				},
				Owner:        "custom-owner",
				Repositories: "",
			},
			wantOwner:    "custom-owner",
			wantReposLen: 0,
			wantErr:      false,
		},
		{
			name: "No owner, with repositories",
			args: Args{
				Pipeline: Pipeline{
					Repo:      "test-owner/test-repo",
					RepoOwner: "test-owner",
					RepoName:  "test-repo",
				},
				Owner:        "",
				Repositories: "repo1,repo2",
			},
			wantOwner:    "test-owner",
			wantReposLen: 2,
			wantErr:      false,
		},
		{
			name: "With owner and repositories",
			args: Args{
				Pipeline: Pipeline{
					Repo:      "test-owner/test-repo",
					RepoOwner: "test-owner",
					RepoName:  "test-repo",
				},
				Owner:        "custom-owner",
				Repositories: "repo1,repo2,repo3",
			},
			wantOwner:    "custom-owner",
			wantReposLen: 3,
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, repos, err := parseOwnerAndRepos(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOwnerAndRepos() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if owner != tt.wantOwner {
				t.Errorf("parseOwnerAndRepos() owner = %v, want %v", owner, tt.wantOwner)
			}
			if len(repos) != tt.wantReposLen {
				t.Errorf("parseOwnerAndRepos() repos length = %v, want %v", len(repos), tt.wantReposLen)
			}
		})
	}
}
