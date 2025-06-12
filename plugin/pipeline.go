// Copyright 2023 the Drone Authors. All rights reserved.
// Use of this source code is governed by the Blue Oak Model License
// that can be found in the LICENSE file.

package plugin

// Pipeline stores drone pipeline metadata.
type Pipeline struct {
	// ID is the pipeline identifier.
	ID string `envconfig:"DRONE_BUILD_NUMBER"`

	// Repository name.
	Repo string `envconfig:"DRONE_REPO"`

	// Repository owner.
	RepoOwner string `envconfig:"DRONE_REPO_OWNER"`

	// Repository name without the owner.
	RepoName string `envconfig:"DRONE_REPO_NAME"`
}
