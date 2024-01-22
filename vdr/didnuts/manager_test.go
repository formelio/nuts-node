/*
 * Copyright (C) 2024 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package didnuts

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/management"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestManager_Create(t *testing.T) {
	ctrl := gomock.NewController(t)
	creator := management.NewMockDocCreator(ctrl)
	owner := management.NewMockDocumentOwner(ctrl)
	manager := NewManager(creator, owner)
	creator.EXPECT().Create(gomock.Any(), gomock.Any()).Return(nil, nil, nil)

	_, _, err := manager.Create(nil, management.DIDCreationOptions{})

	assert.NoError(t, err)
}

func TestManager_IsOwner(t *testing.T) {
	ctrl := gomock.NewController(t)
	creator := management.NewMockDocCreator(ctrl)
	owner := management.NewMockDocumentOwner(ctrl)
	manager := NewManager(creator, owner)
	owner.EXPECT().IsOwner(gomock.Any(), gomock.Any()).Return(false, nil)

	_, err := manager.IsOwner(nil, did.MustParseDID("did:nuts:example.com"))

	assert.NoError(t, err)
}

func TestManager_ListOwned(t *testing.T) {
	ctrl := gomock.NewController(t)
	creator := management.NewMockDocCreator(ctrl)
	owner := management.NewMockDocumentOwner(ctrl)
	manager := NewManager(creator, owner)
	owner.EXPECT().ListOwned(gomock.Any()).Return(nil, nil)

	_, err := manager.ListOwned(nil)

	assert.NoError(t, err)
}

func TestManager_Resolve(t *testing.T) {
	_, _, err := Manager{}.Resolve(did.DID{}, nil)
	assert.EqualError(t, err, "Resolve() is not supported for did:nuts")
}