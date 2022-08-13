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

var _ info.IStore = &Info{}

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

func NewInfo(conf config.Config) *Info {
	return &Info{
		mInfo:  make(map[uuid.UUID]info.TInfo),
		mUsers: initUsers(conf.Admin.Login, conf.Admin.Passwd),
	}
}

func (vInfo *Info) CheckCredentials(login string, password string) (bool, error) {
	vInfo.RLock()
	defer vInfo.RUnlock()

	v, ok := vInfo.mUsers[login]
	if ok {
		if v.Password == password {
			return true, nil
		}

		return false, errors.New("wrong password")
	}

	return false, errors.New("wrong login")
}

func (vInfo *Info) GetUser(login string) (*info.TUser, error) {
	vInfo.RLock()
	defer vInfo.RUnlock()

	v, ok := vInfo.mUsers[login]
	if ok {
		return &v, nil
	}

	return nil, sql.ErrNoRows
}

func (vInfo *Info) CreateInfo(ctx context.Context, data info.TInfo) (uuid.UUID, error) {
	select {
	case <-ctx.Done():
		return uuid.UUID{}, ctx.Err()
	default:
	}

	vInfo.Lock()
	defer vInfo.Unlock()

	vInfo.mInfo[data.FileID] = data

	return data.FileID, nil
}

func (vInfo *Info) ReadInfo(ctx context.Context, fileID uuid.UUID) (*info.TInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	vInfo.RLock()
	defer vInfo.RUnlock()

	data, ok := vInfo.mInfo[fileID]
	if ok {
		return &data, nil
	}

	return nil, sql.ErrNoRows
}

func (vInfo *Info) DeleteInfo(ctx context.Context, fileID uuid.UUID) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	_, ok := vInfo.mInfo[fileID]
	if ok {
		delete(vInfo.mInfo, fileID)
		return nil
	}

	return sql.ErrNoRows
}

func (vInfo *Info) IsExist(ctx context.Context, fileID uuid.UUID) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	vInfo.RLock()
	defer vInfo.RUnlock()

	_, ok := vInfo.mInfo[fileID]
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

	chOut := make(chan info.TInfo, 100)

	go func() {
		defer close(chOut)

		vInfo.RLock()
		defer vInfo.RUnlock()

		for _, data := range vInfo.mInfo {
			select {
			case <-ctx.Done():
				return
			case chOut <- data:
			}
		}
	}()

	return chOut, nil
}
