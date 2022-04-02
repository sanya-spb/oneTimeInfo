package store

import (
	"context"
	"database/sql"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
	"github.com/sanya-spb/oneTimeInfo/internal/config"
)

var _ info.InfoStore = &Info{}

type Info struct {
	sync.RWMutex
	mInfo  map[uuid.UUID]info.TInfo
	mUsers map[string]info.TUser
}

func initUsers(adminLogin string, adminPasswd string) map[string]info.TUser {
	return map[string]info.TUser{
		adminLogin: {
			Login:    adminLogin,
			Password: adminPasswd,
			UID:      1000,
			GID:      1,
		},
		// "user1": {
		// 	Login:    "user1",
		// 	Password: "111",
		// 	UID:      1001,
		// 	GID:      100,
		// },
	}
}

func NewInfo(ctx context.Context, conf config.Config) *Info {
	return &Info{
		mInfo:  make(map[uuid.UUID]info.TInfo),
		mUsers: initUsers(conf.Admin.Login, conf.Admin.Passwd),
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

	info.mInfo[data.FileID] = data

	return data.FileID, nil
}

func (info *Info) ReadInfo(ctx context.Context, fileID uuid.UUID) (*info.TInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	info.RLock()
	defer info.RUnlock()

	data, ok := info.mInfo[fileID]
	if ok {
		return &data, nil
	}

	return nil, sql.ErrNoRows
}

func (info *Info) DeleteInfo(ctx context.Context, fileID uuid.UUID) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	_, ok := info.mInfo[fileID]
	if ok {
		delete(info.mInfo, fileID)
		return nil
	}
	return sql.ErrNoRows
}

func (info *Info) IsExist(ctx context.Context, fileID uuid.UUID) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	info.RLock()
	defer info.RUnlock()

	_, ok := info.mInfo[fileID]
	if ok {
		return true, nil
	}
	return false, nil
}

func (vInfo *Info) ListInfo(ctx context.Context) (chan info.TInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	chout := make(chan info.TInfo, 100)

	go func() {
		defer close(chout)

		vInfo.RLock()
		defer vInfo.RUnlock()

		for _, data := range vInfo.mInfo {
			select {
			case <-ctx.Done():
				return
			case chout <- data:
			}

		}
	}()

	return chout, nil
}
