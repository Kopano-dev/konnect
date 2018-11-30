/*
 * Copyright 2018 Kopano and its licensors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package scopes

import (
	"io/ioutil"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"stash.kopano.io/kc/konnect"
	"stash.kopano.io/kc/konnect/oidc"
)

const (
	scopeAliasBasic = "basic"
	scopeUnknown    = "unknown"
)

const (
	priorityBasic         = 20
	priorityOfflineAccess = 10
)

var defaultScopesMap = map[string]string{
	oidc.ScopeOpenID:  scopeAliasBasic,
	oidc.ScopeEmail:   scopeAliasBasic,
	oidc.ScopeProfile: scopeAliasBasic,

	konnect.ScopeID:           scopeAliasBasic,
	konnect.ScopeUniqueUserID: scopeAliasBasic,
	konnect.ScopeRawSubject:   scopeAliasBasic,
}

var defaultScopesDefinitionMap = map[string]*Definition{
	scopeAliasBasic: &Definition{
		Description: "Access your basic account information",
		Priority:    priorityBasic,
	},
	oidc.ScopeOfflineAccess: &Definition{
		Description: "Keep the allowed access persistently and forever",
		Priority:    priorityOfflineAccess,
	},
}

// Scopes contain collections for scope related meta data
type Scopes struct {
	Mapping     map[string]string      `json:"mapping" yaml:"mapping"`
	Definitions map[string]*Definition `json:"definitions" yaml:"scopes"`
}

// NewScopesFromIDs creates a new scopes meta data collection from the provided
// scopes IDs optionally also adding definitions from a parent.
func NewScopesFromIDs(scopes map[string]bool, parent *Scopes) *Scopes {
	mapping := make(map[string]string)
	definitions := make(map[string]*Definition)

	for scope, enabled := range scopes {
		if !enabled {
			continue
		}

		alias := scope
		if mapped, ok := parent.Mapping[scope]; ok {
			alias = mapped
			mapping[scope] = mapped
		} else if mapped, ok := defaultScopesMap[scope]; ok {
			alias = mapped
			mapping[scope] = mapped
		}

		if definition, ok := parent.Definitions[alias]; ok {
			definitions[alias] = definition
		} else if definition, ok := defaultScopesDefinitionMap[alias]; ok {
			definitions[alias] = definition
		}
	}

	return &Scopes{
		Mapping:     mapping,
		Definitions: definitions,
	}
}

// NewScopesFromFile loads scope definitions from a file.
func NewScopesFromFile(scopesConfFilepath string, logger logrus.FieldLogger) (*Scopes, error) {
	scopes := &Scopes{}

	if scopesConfFilepath != "" {
		logger.Debugf("parsing scopes conf from %v", scopesConfFilepath)
		confFile, err := ioutil.ReadFile(scopesConfFilepath)
		if err != nil {
			return nil, err
		}

		err = yaml.Unmarshal(confFile, scopes)
		if err != nil {
			return nil, err
		}

		for id, definition := range scopes.Definitions {
			fields := logrus.Fields{
				"id":       id,
				"priority": definition.Priority,
			}

			logger.WithFields(fields).Debugln("registered scope")
		}

		for id, mapped := range scopes.Mapping {
			fields := logrus.Fields{
				"id": id,
				"to": mapped,
			}

			logger.WithFields(fields).Debugln("registered scope mapping")
		}
	} else {
		scopes.Mapping = make(map[string]string)
		scopes.Definitions = make(map[string]*Definition)
	}

	return scopes, nil
}

// Extend adds the provided scope mappings and definitions to the accociated
// scopes mappings and definitions with replacing already existing. If scopes is
// nil, Extends is a no-op.
func (s *Scopes) Extend(scopes *Scopes) error {
	if scopes == nil {
		return nil
	}

	for scope, definition := range scopes.Definitions {
		s.Definitions[scope] = definition
	}
	for mapped, mapping := range scopes.Mapping {
		s.Mapping[mapped] = mapping
	}

	return nil
}
