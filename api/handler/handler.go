package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/gofrs/uuid"
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

func (hHandler *Handler) Create(ctx context.Context, vInfo TInfo) (uuid.UUID, error) {
	id, err := hHandler.info.CreateInfo(ctx, info.TInfo(vInfo))
	if err != nil {
		return id, fmt.Errorf("error when creating: %w", err)
	}

	return id, nil
}

func (hHandler *Handler) StatInfo(ctx context.Context, id string) (TInfo, error) {
	if id == "" {
		return TInfo{}, fmt.Errorf("bad request: UUID is empty")
	}

	vUUID, err := uuid.FromString(id)
	if err != nil {
		return TInfo{}, fmt.Errorf("bad request: UUID is wrong")
	}

	data, err := hHandler.info.ReadInfo(ctx, vUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TInfo{}, ErrInfoNotFound
		}
		return TInfo{}, fmt.Errorf("error when reading: %w", err)
	}

	return TInfo(*data), nil
}

func (hHandler *Handler) ReadInfo(ctx context.Context, id string) (TInfo, error) {
	if id == "" {
		return TInfo{}, fmt.Errorf("bad request: ID is empty")
	}

	vUUID, err := uuid.FromString(id)
	if err != nil {
		return TInfo{}, fmt.Errorf("bad request: UUID is wrong")
	}

	delData, err := hHandler.info.ReadInfo(ctx, vUUID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TInfo{}, ErrInfoNotFound
		}
		return TInfo{}, fmt.Errorf("error when deleting: %w", err)
	}

	return TInfo(*delData), nil
}
