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

func (hHandler *Handler) CheckCredentials(login, password string) bool {
	ok, err := hHandler.info.CheckCredentials(login, password)
	if err != nil {
		return false
	}
	if ok {
		return true
	}
	return false
}

func (hHandler *Handler) GetUser(user string) (info.TUser, error) {
	vUser, err := hHandler.info.GetUser(user)
	return *vUser, err
}

func (hHandler *Handler) Create(ctx context.Context, vInfo TInfo) (uint, error) {
	id, err := hHandler.info.CreateInfo(ctx, info.TInfo(vInfo))
	if err != nil {
		return id, fmt.Errorf("error when creating: %w", err)
	}

	return id, nil
}

func (hHandler *Handler) StatInfo(ctx context.Context, fileID uint, serviceID int) (TInfo, error) {
	data, err := hHandler.info.StatInfo(ctx, fileID, serviceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TInfo{}, ErrInfoNotFound
		}
		return TInfo{}, fmt.Errorf("error when reading: %w", err)
	}

	return TInfo(*data), nil
}

func (hHandler *Handler) ReadInfo(ctx context.Context, fileID uint, serviceID int) (TInfo, error) {
	delData, err := hHandler.info.ReadInfo(ctx, fileID, serviceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TInfo{}, ErrInfoNotFound
		}
		return TInfo{}, fmt.Errorf("error when deleting: %w", err)
	}

	return TInfo(*delData), nil
}

func (hHandler *Handler) ListInfo(ctx context.Context) (chan TInfo, error) {
	chin, err := hHandler.info.ListInfo(ctx)
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
