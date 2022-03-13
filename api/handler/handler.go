package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sanya-spb/oneTimeInfo/app/repos/info"
)

type Handler struct {
	info *info.Info
}

func NewHandler(info *info.Info) *Handler {
	r := &Handler{
		info: info,
	}
	return r
}

// TODO: пока берем из пакета info, потом решим что тут лишнее
type TInfo info.TInfo

func (hHandler *Handler) Create(ctx context.Context, vInfo TInfo) (TInfo, error) {
	data, err := hHandler.info.Create(ctx, info.TInfo(vInfo))
	if err != nil {
		return TInfo{}, fmt.Errorf("error when creating: %w", err)
	}

	return TInfo(*data), nil
}

func (hHandler *Handler) Read(ctx context.Context, id string) (TInfo, error) {
	if id == "" {
		return TInfo{}, fmt.Errorf("bad request: ID is empty")
	}

	data, err := hHandler.info.Read(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TInfo{}, ErrInfoNotFound
		}
		return TInfo{}, fmt.Errorf("error when reading: %w", err)
	}

	return TInfo(*data), nil
}

func (hHandler *Handler) Update(ctx context.Context, id string, data TInfo) error {
	if id == "" {
		return fmt.Errorf("bad request: ID is empty")
	}

	err := hHandler.info.Update(ctx, id, info.TInfo(data))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInfoNotFound
		}
		return fmt.Errorf("error when updating: %w", err)
	}

	return nil
}

func (hHandler *Handler) UpdateRet(ctx context.Context, id string, data TInfo) (TInfo, error) {
	if id == "" {
		return TInfo{}, fmt.Errorf("bad request: ID is empty")
	}

	newData, err := hHandler.info.UpdateRet(ctx, id, info.TInfo(data))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TInfo{}, ErrInfoNotFound
		}
		return TInfo{}, fmt.Errorf("error when updating: %w", err)
	}

	return TInfo(*newData), nil
}

func (hHandler *Handler) Delete(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("bad request: ID is empty")
	}

	err := hHandler.info.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInfoNotFound
		}
		return fmt.Errorf("error when deleting: %w", err)
	}

	return nil
}

func (hHandler *Handler) DeleteRet(ctx context.Context, id string) (TInfo, error) {
	if id == "" {
		return TInfo{}, fmt.Errorf("bad request: ID is empty")
	}

	delData, err := hHandler.info.DeleteRet(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TInfo{}, ErrInfoNotFound
		}
		return TInfo{}, fmt.Errorf("error when deleting: %w", err)
	}

	return TInfo(*delData), nil
}

func (hHandler *Handler) Go(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("bad request: ID is empty")
	}

	data, err := hHandler.info.Go(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrInfoNotFound
		}
		return "", fmt.Errorf("error when reading: %w", err)
	}

	return data, nil
}

func (hHandler *Handler) Stat(ctx context.Context) (chan TInfo, error) {
	chin, err := hHandler.info.Stat(ctx)
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
				chout <- TInfo(data)
			}
		}
	}()

	return chout, nil
}
