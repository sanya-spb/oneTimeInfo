package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
	"github.com/sanya-spb/oneTimeInfo/internal/config"
)

var _ info.InfoStore = &Info{}

type Info struct {
	sync.RWMutex
	rdb    *redis.Client
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
		rdb: redis.NewClient(&redis.Options{
			Addr:     conf.Store.Address + ":" + strconv.Itoa(int(conf.Store.Port)),
			Password: conf.Store.Passwd,
			DB:       0, // use default DB
		}),
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
		} else {
			return false, errors.New("Wrong password")
		}
	}

	return false, errors.New("Wrong login")
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

	value, err := json.Marshal(data)
	if err != nil {
		return uuid.UUID{}, err
	}

	err = vInfo.rdb.Set(ctx, data.FileID.String(), value, data.DeleteAt.Sub(time.Now())).Err()
	if err != nil {
		return uuid.UUID{}, err
	}

	return data.FileID, nil
}

func (vInfo *Info) ReadInfo(ctx context.Context, fileID uuid.UUID) (*info.TInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	value, err := vInfo.rdb.Get(ctx, fileID.String()).Result()
	if err != nil {
		return nil, err
	}
	var data info.TInfo
	err = json.Unmarshal([]byte(value), &data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

func (vInfo *Info) DeleteInfo(ctx context.Context, fileID uuid.UUID) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	err := vInfo.rdb.Del(ctx, fileID.String()).Err()
	if err != nil {
		return err
	}

	return nil
}

func (vInfo *Info) IsExist(ctx context.Context, fileID uuid.UUID) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	_, err := vInfo.rdb.Get(ctx, fileID.String()).Result()
	if err == redis.Nil {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
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

		iter := vInfo.rdb.Scan(ctx, 0, "*", 0).Iterator()
		for iter.Next(ctx) {
			value, err := vInfo.rdb.Get(ctx, iter.Val()).Result()
			if err != nil {
				return
			}
			var data info.TInfo
			err = json.Unmarshal([]byte(value), &data)
			if err != nil {
				return
			}

			select {
			case <-ctx.Done():
				return
			case chout <- data:
			}
		}
		if err := iter.Err(); err != nil {
			return
		}
	}()

	return chout, nil
}
