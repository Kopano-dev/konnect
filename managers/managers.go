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

package managers

import (
	"fmt"
)

// ServiceUsesManagers is an interface for service which register to managers.
type ServiceUsesManagers interface {
	RegisterManagers(mgrs *Managers) error
}

// Managers is a registry for named managers.
type Managers struct {
	registry map[string]interface{}
}

// New creates a new Managers.
func New() *Managers {
	return &Managers{
		registry: make(map[string]interface{}),
	}
}

// Set adds the provided manager with the provided name to the accociated
// Managers.
func (m *Managers) Set(name string, manager interface{}) {
	m.registry[name] = manager
}

// Get returns the manager identified by the given name from the accociated
// managers.
func (m *Managers) Get(name string) (interface{}, bool) {
	manager, ok := m.registry[name]

	return manager, ok
}

// Must returns the manager indentified by the given name or panics.
func (m *Managers) Must(name string) interface{} {
	manager, ok := m.Get(name)
	if !ok {
		panic(fmt.Errorf("manager %s not found", name))
	}

	return manager
}

// Apply registers the accociated manager's registered managers.
func (m *Managers) Apply() error {
	for _, manager := range m.registry {
		if service, ok := manager.(ServiceUsesManagers); ok {
			err := service.RegisterManagers(m)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
