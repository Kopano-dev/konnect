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

package meta

import (
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

var defaultScopesDefinitionMap = map[string]*ScopeDefinition{
	scopeAliasBasic: &ScopeDefinition{
		Description: "Access your basic account information",
		Priority:    priorityBasic,
	},
	oidc.ScopeOfflineAccess: &ScopeDefinition{
		Description: "Keep the allowed access persistently and forever",
		Priority:    priorityOfflineAccess,
	},
}

// Scopes contain collections for scope related meta data
type Scopes struct {
	Mapping     map[string]string           `json:"mapping"`
	Definitions map[string]*ScopeDefinition `json:"definitions"`
}

// NewScopesFromIDs creates a new scopes meta data collection from the provided
// scopes IDs optionally also adding definitions from a parent.
func NewScopesFromIDs(scopes map[string]bool, parent *Scopes) *Scopes {
	mapping := make(map[string]string)
	definitions := make(map[string]*ScopeDefinition)

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

// A ScopeDefinition contains the meta data for a single scope.
type ScopeDefinition struct {
	Priority    int    `json:"priority"`
	Description string `json:"description"`
}
