package store

import (
	"context"
	"database/sql"
	"math/rand"
	"sync"
	"time"

	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
)

var _ info.InfoStore = &Info{}

type Info struct {
	sync.RWMutex
	m map[string]info.TInfo
}

func NewLinks() *Info {
	return &Info{
		m: make(map[string]info.TInfo),
	}
}

func (info *Info) Create(ctx context.Context, data info.TInfo) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	id, err := info.GetNextID(ctx)
	if err != nil {
		return "", nil
	}
	data.ID = id

	info.Lock()
	defer info.Unlock()

	info.m[data.ID] = data
	return id, nil
}

func (info *Info) Read(ctx context.Context, id string) (*info.TInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	info.RLock()
	defer info.RUnlock()

	data, ok := info.m[id]
	if ok {
		return &data, nil
	}
	return nil, sql.ErrNoRows
}

func (info *Info) Update(ctx context.Context, id string, data info.TInfo) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if ok, err := info.IsExist(ctx, id); err != nil {
		return err
	} else {
		if !ok {
			return sql.ErrNoRows
		}
	}

	data.ID = id

	info.Lock()
	defer info.Unlock()

	info.m[data.ID] = data
	return nil
}

func (info *Info) UpdateRet(ctx context.Context, id string, data info.TInfo) (*info.TInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if ok, err := info.IsExist(ctx, id); err != nil {
		return nil, err
	} else {
		if !ok {
			return nil, sql.ErrNoRows
		}
	}

	data.ID = id

	info.Lock()
	defer info.Unlock()

	info.m[data.ID] = data
	return &data, nil
}

func (info *Info) Delete(ctx context.Context, id string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	_, ok := info.m[id]
	if ok {
		delete(info.m, id)
		return nil
	}
	return sql.ErrNoRows
}

func (info *Info) DeleteRet(ctx context.Context, id string) (*info.TInfo, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	info.Lock()
	defer info.Unlock()

	data, ok := info.m[id]
	if ok {
		delete(info.m, id)
		return &data, nil
	}
	return nil, sql.ErrNoRows
}

func (info *Info) IsExist(ctx context.Context, id string) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}

	info.RLock()
	defer info.RUnlock()

	_, ok := info.m[id]
	if ok {
		return true, nil
	}
	return false, nil
}

func (info *Info) GetNextID(ctx context.Context) (string, error) {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	n := 6

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}

		b := make([]rune, n)
		for i := range b {
			b[i] = letterRunes[rand.Intn(len(letterRunes))]
		}
		if ok, err := info.IsExist(ctx, string(b)); err != nil {
			return "", err
		} else {
			if ok {
				continue
			}
		}
		return string(b), nil
	}
}

func (info *Info) Go(ctx context.Context, id string) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	info.Lock()
	defer info.Unlock()

	data, ok := info.m[id]
	if ok {
		if info.m[id].DeleteAt.Before(time.Now()) {
			return "", sql.ErrNoRows
		}
		// data.GoCount++
		info.m[id] = data
		return data.URL, nil
	}
	return "", sql.ErrNoRows
}

func (vInfo *Info) Stat(ctx context.Context) (chan info.TInfo, error) {
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

		for _, data := range vInfo.m {
			select {
			case <-ctx.Done():
				return
			case chout <- data:
			}

		}
	}()

	return chout, nil
}
