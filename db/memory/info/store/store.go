package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"github.com/gofrs/uuid"
	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
)

var _ info.InfoStore = &Info{}

type Info struct {
	sync.RWMutex
	mInfo  map[string]info.TInfo
	mUsers map[string]info.TUser
}

func initUsers() map[string]info.TUser {
	return map[string]info.TUser{
		"admin": {
			Login:    "admin",
			Password: "111",
			UID:      1000,
			GID:      1,
		},
		"user1": {
			Login:    "user1",
			Password: "111",
			UID:      1001,
			GID:      100,
		},
		"user2": {
			Login:    "user2",
			Password: "222",
			UID:      1002,
			GID:      100,
		},
	}
}

func NewInfo() *Info {
	return &Info{
		mInfo:  make(map[string]info.TInfo),
		mUsers: initUsers(),
	}
}

func (info *Info) CheckCredentials(login string, password string) (bool, error) {
	info.RLock()
	defer info.RUnlock()

	v, ok := info.mUsers[login]
	if ok {
		if v.Password == password {
			return true, nil
		} else {
			return false, errors.New("Wrong password")
		}
	}

	return false, errors.New("Wrong login")
}

func (info *Info) Creds() map[string]string {

	return nil
}

func (info *Info) GetUser(login string) (*info.TUser, error) {
	info.RLock()
	defer info.RUnlock()

	v, ok := info.mUsers[login]
	if ok {
		return &v, nil
	}

	return nil, sql.ErrNoRows
}

func (info *Info) CreateInfo(ctx context.Context, data info.TInfo) (uuid.UUID, error) {
	select {
	case <-ctx.Done():
		return uuid.UUID{}, ctx.Err()
	default:
	}

	info.Lock()
	defer info.Unlock()

	info.mInfo[data.UUID.String()] = data

	return data.UUID, nil
}

func (info *Info) ReadInfo(ctx context.Context, uuid uuid.UUID) (*info.TInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	info.RLock()
	defer info.RUnlock()

	data, ok := info.mInfo[uuid.String()]
	if ok {
		return &data, nil
	}

	return nil, sql.ErrNoRows
}

func (info *Info) DeleteInfo(ctx context.Context, uuid uuid.UUID) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	_, ok := info.mInfo[uuid.String()]
	if ok {
		delete(info.mInfo, uuid.String())
		return nil
	}
	return sql.ErrNoRows
}

func (info *Info) IsExist(ctx context.Context, uuid uuid.UUID) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	info.RLock()
	defer info.RUnlock()

	_, ok := info.mInfo[uuid.String()]
	if ok {
		return true, nil
	}
	return false, nil
}
