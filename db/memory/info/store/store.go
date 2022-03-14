package store

import (
	"context"
	"database/sql"
	"sync"

	"github.com/gofrs/uuid"
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

func (info *Info) CreateInfo(ctx context.Context, data info.TInfo) (uuid.UUID, error) {
	select {
	case <-ctx.Done():
		return uuid.UUID{}, ctx.Err()
	default:
	}

	info.Lock()
	defer info.Unlock()

	info.m[data.UUID.String()] = data

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

	data, ok := info.m[uuid.String()]
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

	_, ok := info.m[uuid.String()]
	if ok {
		delete(info.m, uuid.String())
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

	_, ok := info.m[uuid.String()]
	if ok {
		return true, nil
	}
	return false, nil
}
