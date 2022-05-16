// Copyright 2021 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import "strings"

func promoteBuildPipeline() pipeline {
	// TODO: migrate

	aptPipeline := promoteAptPipeline()
	return aptPipeline
}

// This function calls the build-apt-repos tool which handles the APT portion of RFD 0058.
func promoteAptPipeline() pipeline {
	aptVolumeName := "aptrepo"

	p := newKubePipeline("publish-apt-new-repos")
	// p.Trigger = triggerPromote
	p.Trigger = trigger{
		Event:  triggerRef{Include: []string{"push"}},
		Branch: triggerRef{Include: []string{"rfd/0058-package-distribution"}},
	}
	for _, pipeline := range tagPipelines() {
		if !strings.Contains(pipeline.Name, debPackage) {
			continue
		}
		p.DependsOn = append(p.DependsOn, pipeline.Name)
	}
	p.Workspace = workspace{Path: "/go"}
	p.Volumes = []volume{
		{
			Name: aptVolumeName,
			Claim: &volumeClaim{
				Name: "drone-s3-aptrepo-pvc",
			},
		},
		volumeTmpfs,
	}
	p.Steps = []step{
		{
			Name:  "Check out code",
			Image: "alpine:git",
			Environment: map[string]value{
				"GITHUB_PRIVATE_KEY": {
					fromSecret: "GITHUB_PRIVATE_KEY",
				},
			},
			Commands: tagCheckoutCommands(false),
		},
		{
			Name:  "Publish debs to APT repos",
			Image: "golang:1.18.1-bullseye",
			Environment: map[string]value{
				"APT_S3_BUCKET": {
					fromSecret: "APT_REPO_NEW_AWS_S3_BUCKET",
				},
				"AWS_ACCESS_KEY_ID": {
					fromSecret: "APT_REPO_NEW_AWS_ACCESS_KEY_ID",
				},
				"AWS_SECRET_ACCESS_KEY": {
					fromSecret: "APT_REPO_NEW_AWS_SECRET_ACCESS_KEY",
				},
				"GNUPGHOME": {
					raw: "/tmpfs/gnupg",
				},
				"GPG_RPM_SIGNING_ARCHIVE": {
					fromSecret: "GPG_RPM_SIGNING_ARCHIVE",
				},
			},
			Commands: []string{
				"mkdir -m0700 $GNUPGHOME",
				"echo \"$GPG_RPM_SIGNING_ARCHIVE\" | base64 -d | tar -xzf - -C $GNUPGHOME",
				"chown -R root:root $GNUPGHOME", // This probably won't work (gpg1 needs to be able to read it), but it's worth trying
				"apt update",
				"apt install aptly -y",
				"cd /go/src/github.com/gravitational/teleport/build.assets/tooling",
				"export VERSION=\"v`cat /go/build/CURRENT_VERSION_TAG_GENERIC.txt`\"",
				"export RELEASE_CHANNEL=\"stable\"", // The tool supports several release channels but I'm not sure where this should be configured
				strings.Join(
					[]string{
						// This just makes the (long) command a little more readable
						"go run ./cmd/build-apt-repos",
						"-bucket \"$APT_S3_BUCKET\"",
						"-artifact-major-version \"$VERSION\"",
						"-artifact-release-channel \"$RELEASE_CHANNEL\"",
						"-artifact-path \"/go/artifacts/\"",
						"-log-level 4", // Set this to 5 for debug logging
					},
					" ",
				),
			},
			Volumes: []volumeRef{
				{
					Name: aptVolumeName,
					Path: "/repo_bucket",
				},
				volumeRefTmpfs,
			},
		},
	}

	return p
}

func updateDocsPipeline() pipeline {
	// TODO: migrate
	return pipeline{}
}
