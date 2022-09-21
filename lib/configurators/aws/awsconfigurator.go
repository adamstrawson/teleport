// Copyright 2022 Gravitational, Inc
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

package aws

import (
	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/lib/config"
	"github.com/gravitational/teleport/lib/configurators"
)

// BootstrapFlags flags provided by users to configure and define how the
// configurators will work.
type BootstrapFlags struct {
	DiscoveryService bool
	// ConfigPath database agent configuration path.
	ConfigPath string
	// Manual boolean indicating if the configurator will perform the
	// instructions or if it will be the user.
	Manual bool
	// PolicyName name of the generated policy.
	PolicyName string
	// AttachToUser user that the generated policies will be attached to.
	AttachToUser string
	// AttachToRole role that the generated policies will be attached to.
	AttachToRole string
	// ForceRDSPermissions forces the presence of RDS permissions.
	ForceRDSPermissions bool
	// ForceRedshiftPermissions forces the presence of Redshift permissions.
	ForceRedshiftPermissions bool
	// ForceElastiCachePermissions forces the presence of ElastiCache permissions.
	ForceElastiCachePermissions bool
	// ForceMemoryDBPermissions forces the presence of MemoryDB permissions.
	ForceMemoryDBPermissions bool
	// ForceEC2Permissions forces the presence of EC2 permissions.
	ForceEC2Permissions bool
}

// BuildConfigurators reads the configuration and returns a list of
// configurators. Configurators that are "empty" are not returned.
func BuildConfigurators(flags BootstrapFlags) ([]configurators.Configurator, error) {
	fileConfig, err := config.ReadFromFile(flags.ConfigPath)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	aws, err := NewAWSConfigurator(ConfiguratorConfig{
		Flags:      flags,
		FileConfig: fileConfig,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	var configurators []configurators.Configurator
	if !aws.IsEmpty() {
		configurators = append(configurators, aws)
	}

	return configurators, nil
}
