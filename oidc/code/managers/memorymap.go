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

package managers

import (
	"context"
	"time"

	"stash.kopano.io/kc/konnect/identity"
	"stash.kopano.io/kc/konnect/oidc/code"
	"stash.kopano.io/kc/konnect/oidc/payload"
	"stash.kopano.io/kc/konnect/rndm"

	"github.com/orcaman/concurrent-map"
)

const (
	codeValidDuration = 2 * time.Minute
)

// Manager provides the api and state for OIDC code generation and token
// exchange. The CodeManager's methods are safe to call from multiple Go
// routines.
type memoryMapManager struct {
	table        cmap.ConcurrentMap
	codeDuration time.Duration
}

type codeRequestRecord struct {
	ar   *payload.AuthenticationRequest
	auth identity.AuthRecord
	when time.Time
}

// NewMemoryMapManager creates a new CodeManager.
func NewMemoryMapManager(ctx context.Context) code.Manager {
	cm := &memoryMapManager{
		table: cmap.New(),
	}

	// Cleanup function.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				cm.purgeExpired()
			case <-ctx.Done():
				return
			}

		}
	}()

	return cm
}

func (cm *memoryMapManager) purgeExpired() {
	expired := make([]string, 0)
	deadline := time.Now().Add(-codeValidDuration)
	var record *codeRequestRecord
	for entry := range cm.table.IterBuffered() {
		record = entry.Val.(*codeRequestRecord)
		if record.when.Before(deadline) {
			expired = append(expired, entry.Key)
		}
	}
	for _, code := range expired {
		cm.table.Remove(code)
	}
}

// Create creates a new random code string, stores it together with the provided
// values in the accociated CodeManager's table and returns the code.
func (cm *memoryMapManager) Create(ar *payload.AuthenticationRequest, auth identity.AuthRecord) (string, error) {
	code, err := rndm.GenerateRandomString(24)
	if err != nil {
		return "", err
	}

	record := &codeRequestRecord{
		ar:   ar,
		auth: auth,
		when: time.Now(),
	}
	cm.table.Set(code, record)

	return code, nil
}

// Pop looks up the provided code in the accociated CodeManagers's table. If
// found it returns the authentication request and backend record plus true.
// When not found, both values return as nil plus false.
func (cm *memoryMapManager) Pop(code string) (*payload.AuthenticationRequest, identity.AuthRecord, bool) {
	stored, found := cm.table.Pop(code)
	if !found {
		return nil, nil, false
	}
	record := stored.(*codeRequestRecord)

	return record.ar, record.auth, true
}
