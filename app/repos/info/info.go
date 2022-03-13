package info

import (
	"context"
	"fmt"
	"time"
)

type TInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	URL       string    `json:"url"`
	Descr     string    `json:"descr"`
	CreatedAt time.Time `json:"created_at"`
	DeleteAt  time.Time `json:"delete_at"`
}

type InfoStore interface {
	Create(ctx context.Context, data TInfo) (string, error)
	Read(ctx context.Context, id string) (*TInfo, error)
	Update(ctx context.Context, id string, data TInfo) error
	UpdateRet(ctx context.Context, id string, data TInfo) (*TInfo, error)
	Delete(ctx context.Context, id string) error
	DeleteRet(ctx context.Context, id string) (*TInfo, error)
	IsExist(ctx context.Context, id string) (bool, error)
	GetNextID(ctx context.Context) (string, error)
	Go(ctx context.Context, id string) (string, error)
	Stat(ctx context.Context) (chan TInfo, error)
}

type Info struct {
	store InfoStore
}

func NewInfo(store InfoStore) *Info {
	return &Info{
		store: store,
	}
}

// Create new data with returning it
func (info *Info) Create(ctx context.Context, data TInfo) (*TInfo, error) {
	id, err := info.store.Create(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("create data error: %w", err)
	}
	data.ID = id
	return &data, nil
}

// Return Link by ID
func (info *Info) Read(ctx context.Context, id string) (*TInfo, error) {
	data, err := info.store.Read(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("read data error: %w", err)
	}
	return data, nil
}

// Update Link by ID
func (info *Info) Update(ctx context.Context, id string, data TInfo) error {
	err := info.store.Update(ctx, id, data)
	if err != nil {
		return fmt.Errorf("update data error: %w", err)
	}
	return nil
}

// Update Link by ID with returning updated Link
func (info *Info) UpdateRet(ctx context.Context, id string, data TInfo) (*TInfo, error) {
	lNew, err := info.store.UpdateRet(ctx, id, data)
	if err != nil {
		return nil, fmt.Errorf("update data error: %w", err)
	}
	return lNew, nil
}

// Delete Link by ID
func (info *Info) Delete(ctx context.Context, id string) error {
	err := info.store.Delete(ctx, id)
	if err != nil {
		return fmt.Errorf("delete data error: %w", err)
	}
	return nil
}

// Delete by ID with returning deleted Link
func (info *Info) DeleteRet(ctx context.Context, id string) (*TInfo, error) {
	dLink, err := info.store.DeleteRet(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("delete data error: %w", err)
	}
	return dLink, nil
}

// Return URL by ID for redirection
func (info *Info) Go(ctx context.Context, id string) (string, error) {
	// return url.URL{ Scheme: "https", Host: r.Host, Path: r.URL.Path, RawQuery: r.URL.RawQuery, }
	data, err := info.store.Go(ctx, id)
	if err != nil {
		return "", fmt.Errorf("redirect data error: %w", err)
	}
	return data, nil
}

func (info *Info) Stat(ctx context.Context) (chan TInfo, error) {
	chin, err := info.store.Stat(ctx)
	if err != nil {
		return nil, err
	}
	chout := make(chan TInfo, 100)

	go func() {
		defer close(chout)
		for {
			select {
			case <-ctx.Done():
				return
			case data, ok := <-chin:
				if !ok {
					return
				}
				chout <- data
			}
		}
	}()

	return chout, nil
}
