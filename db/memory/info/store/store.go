package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
)

var _ info.InfoStore = &Info{}

type Info struct {
	sync.RWMutex
	mInfo      map[uint]info.TInfo
	mInfoMaxID uint
	mUsers     map[string]info.TUser
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

func initInfo() map[uint]info.TInfo {
	return map[uint]info.TInfo{
		1: {
			FileID:     1,
			Name:       "file1",
			Descr:      "descr1",
			Size:       111,
			IsFile:     true,
			CreatedAt:  time.Now().Add(-time.Hour * 24),
			DeleteAt:   time.Now().Add(time.Hour * 24 * 14),
			DataBase64: base64.StdEncoding.EncodeToString([]byte("data1")),
		},
		2: {
			FileID:     2,
			Name:       "message2",
			Descr:      "descr2",
			Size:       111,
			IsFile:     false,
			CreatedAt:  time.Now().Add(-time.Hour * 24),
			DeleteAt:   time.Now().Add(time.Hour * 24 * 14),
			DataBase64: base64.StdEncoding.EncodeToString([]byte("data2")),
		},
	}
}

func NewInfo() *Info {
	return &Info{
		// mInfo:  make(map[uint]info.TInfo),
		mInfo:      initInfo(),
		mInfoMaxID: 2,
		mUsers:     initUsers(),
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

func (info *Info) GetNextFileID() (uint, error) {
	info.Lock()
	defer info.Unlock()

	info.mInfoMaxID++

	return info.mInfoMaxID, nil
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

func (info *Info) CreateInfo(ctx context.Context, data info.TInfo) (uint, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	info.Lock()
	defer info.Unlock()

	info.mInfo[data.FileID] = data

	return data.FileID, nil
}

func (info *Info) ReadInfo(ctx context.Context, fileID uint, serviceID int) (*info.TInfo, error) {
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

func (info *Info) DeleteInfo(ctx context.Context, fileID uint, serviceID int) error {
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

func (info *Info) IsExist(ctx context.Context, fileID uint, serviceID int) (bool, error) {
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
