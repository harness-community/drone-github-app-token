# Drone GitHub App Token Plugin

A Drone plugin for creating a GitHub App Installation Access Token.

## Usage

This plugin can be used to create a GitHub App installation access token in your Drone pipelines. The token can be used for repository or organizational access with specified permissions.

### Example Pipeline YAML

```yaml
              - step:
                  identifier: Plugin_1
                  type: Plugin
                  name: Plugin_1
                  spec:
                    connectorRef: opopensourceops
                    image: harnesscommunitytest/drone-github-app-token:test
                    settings:
                      app_id: "1398395"
                      private_key: <+secrets.getValue("opgithubappkey")> # Harness Secret of Type "File"
                      permission_contents: write
              - step:
                  identifier: Run_1
                  type: Run
                  name: Run_1
                  spec:
                    shell: Sh
                    command: "curl -H \"Authorization: token <+execution.steps.Plugin_1.output.outputVariables.GITHUB_APP_TOKEN>\"\
                      \ https://api.github.com/repos/ompragash/notes/contents"
```

### Settings

| Setting | Description | Required | Default |
|---------|-------------|----------|---------|
| `app_id` | GitHub App ID | Yes | |
| `private_key` | GitHub App private key | Yes | |
| `owner` | The owner of the GitHub App installation | No | Repository owner from pipeline context |
| `repositories` | Comma or newline-separated list of repositories to install the GitHub App on | No | Current repository from pipeline context |
| `skip_token_revoke` | If true, the token will not be revoked when the job completes | No | `false` |
| `github_api_url` | The URL of the GitHub REST API | No | `https://api.github.com` |
| `log_level` | Log level for more detailed output (`debug` or `trace`) | No | `info` |

### Permission Settings

You can specify the permissions you want to grant to the token. Each permission can be set to `read` or `write` (and in some cases `admin`).

For example:

```yaml
steps:
  - name: create-token
    image: harnesscommunitytest/drone-github-app-token
    settings:
      app_id: 
        from_secret: github_app_id
      private_key:
        from_secret: github_app_private_key
      permission_contents: write
      permission_issues: read
      permission_pull_requests: write
```

Here's the full list of available permission settings:

| Permission Setting | Description |
|-------------------|-------------|
| `permission_actions` | Permission for GitHub Actions workflows, workflow runs, and artifacts |
| `permission_administration` | Permission for repository creation, deletion, settings, teams, and collaborators creation |
| `permission_checks` | Permission for checks on code |
| `permission_codespaces` | Permission to create, edit, delete, and list Codespaces |
| `permission_contents` | Permission for repository contents, commits, branches, downloads, releases, and merges |
| `permission_dependabot_secrets` | Permission to manage Dependabot secrets |
| `permission_deployments` | Permission for deployments and deployment statuses |
| `permission_email_addresses` | Permission to manage email addresses belonging to a user |
| `permission_environments` | Permission for managing repository environments |
| `permission_followers` | Permission to manage followers belonging to a user |
| `permission_git_ssh_keys` | Permission to manage git SSH keys |
| `permission_gpg_keys` | Permission to view and manage GPG keys belonging to a user |
| `permission_interaction_limits` | Permission to view and manage interaction limits on a repository |
| `permission_issues` | Permission for issues and related comments, assignees, labels, and milestones |
| `permission_members` | Permission for organization teams and members |
| `permission_metadata` | Permission to search repositories, list collaborators, and access repository metadata |
| `permission_organization_administration` | Permission to manage organization settings |
| `permission_organization_announcement_banners` | Permission to view and manage announcement banners for an organization |
| `permission_organization_copilot_seat_management` | Permission to manage Copilot seats for an organization |
| `permission_organization_custom_properties` | Permission to view and manage custom properties for an organization |
| `permission_organization_events` | Permission to view events for an organization |
| `permission_organization_hooks` | Permission to manage the post-receive hooks for an organization |
| `permission_organization_packages` | Permission for organization packages published to GitHub Packages |
| `permission_organization_personal_access_token_requests` | Permission to view and manage personal access token requests for an organization |
| `permission_organization_personal_access_token_requests_management` | Permission to manage personal access token requests for an organization |
| `permission_organization_personal_access_tokens` | Permission to view and manage personal access tokens for an organization |
| `permission_organization_projects` | Permission to manage organization projects and projects public preview |
| `permission_organization_secrets` | Permission to manage organization secrets |
| `permission_organization_self_hosted_runners` | Permission to view and manage GitHub Actions self-hosted runners available to an organization |
| `permission_organization_user_blocking` | Permission to view and manage users blocked by the organization |
| `permission_packages` | Permission for packages published to GitHub Packages |
| `permission_pages` | Permission to retrieve Pages statuses, configuration, and builds, as well as create new builds |
| `permission_profile` | Permission to manage the profile settings belonging to a user |
| `permission_pull_requests` | Permission for pull requests and related comments, assignees, labels, milestones, and merges |
| `permission_repository_custom_properties` | Permission to view and edit custom properties for a repository |
| `permission_repository_hooks` | Permission to manage the post-receive hooks for a repository |
| `permission_repository_projects` | Permission to manage repository projects, columns, and cards |
| `permission_secret_scanning_alerts` | Permission to view and manage secret scanning alerts |
| `permission_secrets` | Permission to manage repository secrets |
| `permission_security_events` | Permission to view and manage security events like code scanning alerts |
| `permission_single_file` | Permission to manage just a single file |
| `permission_starring` | Permission to list and manage repositories a user is starring |
| `permission_statuses` | Permission for commit statuses |
| `permission_team_discussions` | Permission to manage team discussions and related comments |
| `permission_vulnerability_alerts` | Permission to manage Dependabot alerts |
| `permission_workflows` | Permission to update GitHub Actions workflow files |

## Output

The plugin will set the following environment variables:

| Variable | Description |
|----------|-------------|
| `GITHUB_APP_TOKEN` | GitHub installation access token |
| `GITHUB_APP_INSTALLATION_ID` | GitHub App installation ID |
| `GITHUB_APP_SLUG` | GitHub App slug |

These can be used in subsequent pipeline steps.
