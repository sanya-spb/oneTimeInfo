package info

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-chi/oauth"
	"github.com/gofrs/uuid"
)

type TInfo struct {
	UUID      uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Descr     string    `json:"descr"`
	Size      uint64    `json:"size"`
	IsFile    bool      `json:"as_file"`
	CreatedAt time.Time `json:"created_at"`
	DeleteAt  time.Time `json:"delete_at"`
	UserID    string    `json:"user_id"`
	Data      []byte    `json:"data"`
}

type InfoStore interface {
	CreateInfo(ctx context.Context, data TInfo) (uuid.UUID, error)
	ReadInfo(ctx context.Context, uuid uuid.UUID) (*TInfo, error)
	DeleteInfo(ctx context.Context, uuid uuid.UUID) error
	// CheckAuth(ctx context.Context) error
}

type Info struct {
	store InfoStore
}

func NewInfo(store InfoStore) *Info {
	return &Info{
		store: store,
	}
}

// Create new data with returning it UUID
func (info *Info) CreateInfo(ctx context.Context, data TInfo) (uuid.UUID, error) {
	var err error

	data.UUID, err = uuid.NewV4()
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("create data error: %w", err)
	}

	_, err = info.store.CreateInfo(ctx, data)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("create data error: %w", err)
	}

	return data.UUID, nil
}

// Get Info by UUID
func (info *Info) ReadInfo(ctx context.Context, uuid uuid.UUID) (*TInfo, error) {
	data, err := info.store.ReadInfo(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("read data error: %w", err)
	}

	claim := ctx.Value(oauth.ClaimsContext).(map[string]string)
	if claim["user_id"] != data.UserID {
		return nil, errors.New("read permission error")
	}

	err = info.store.DeleteInfo(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("delete data error: %w", err)
	}

	return data, nil
}

// Get Stat by UUID
func (info *Info) StatInfo(ctx context.Context, uuid uuid.UUID) (*TInfo, error) {
	data, err := info.store.ReadInfo(ctx, uuid)
	if err != nil {
		return nil, fmt.Errorf("read data error: %w", err)
	}
	data.Data = []byte{}
	return data, nil
}
