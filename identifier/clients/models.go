/*
 * Copyright 2017 Kopano and its licensors
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

package clients

import (
	_ "gopkg.in/yaml.v2" // Make sure we have yaml.
)

// RegistryData is the base structur of our client registry configuration file.
type RegistryData struct {
	Clients []*ClientRegistration `yaml:"clients,flow"`
}

// ClientRegistration defines a client with its properties.
type ClientRegistration struct {
	ID              string `yaml:"id"`
	Secret          string `yaml:"secret"`
	Name            string `yaml:"name"`
	ApplicationType string `yaml:"application_type"`

	Trusted  bool `yaml:"trusted"`
	Insecure bool `yaml:"insecure"`

	RedirectURIs []string `yaml:"redirect_uris,flow"`
	Origins      []string `yaml:"origins,flow"`
}
