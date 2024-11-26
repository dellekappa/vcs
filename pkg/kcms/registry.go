/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kcms

type Registry struct {
	defaultVCSKeyManager  VCSKeyCertManager
	defaultConfig         Config
	defaultMetricProvider metricsProvider
}

func NewRegistry(
	defaultVCSKeyManager VCSKeyCertManager,
	defaultKmsConfig Config,
	defaultMetricProvider metricsProvider,
) *Registry {
	return &Registry{
		defaultConfig:         defaultKmsConfig,
		defaultVCSKeyManager:  defaultVCSKeyManager,
		defaultMetricProvider: defaultMetricProvider,
	}
}

func (r *Registry) GetKeyCertManager(config *Config) (VCSKeyCertManager, error) {
	if config == nil {
		return r.defaultVCSKeyManager, nil
	}

	cfgCopy := r.defaultConfig
	cfgCopy.KMSType = config.KMSType
	if config.MasterKey != "" {
		cfgCopy.MasterKey = config.MasterKey
	}

	return NewAriesKeyCertManager(&cfgCopy, r.defaultMetricProvider)
}
