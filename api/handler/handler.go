package handler

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
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

type Token info.Token

// TInfo - describes the stored secret unit of information
type TInfo struct {
	FileID     uuid.UUID `json:"id"`         // UUID
	Name       string    `json:"name"`       // Name of the secret unit
	Descr      string    `json:"descr"`      // Description of the secret unit
	Size       int       `json:"size"`       // Size of secret unit
	IsFile     bool      `json:"as_file"`    // IsFile the flag indicates that this secret is a file
	CreatedAt  time.Time `json:"created_at"` // date of creation secret unit
	DeleteAt   time.Time `json:"delete_at"`  // date of expiration secret unit
	DataBase64 string    `json:"data"`       // The secret unit

}

// CheckCredentials checks if exist user with given login and password
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

// EncryptToken convert Token struct to encrypted string
func (hHandler *Handler) EncryptToken(token Token) (string, error) {
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return "", fmt.Errorf("token serialization error: %s", err.Error())
	}

	encryptedToken, err := hHandler.info.EncryptStr(tokenJSON)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedToken), nil
}

// DecryptToken convert encrypted string to Token struct
func (hHandler *Handler) DecryptToken(encryptedTokenBase64 string) (*Token, error) {
	encryptedToken, err := base64.StdEncoding.DecodeString(encryptedTokenBase64)
	if err != nil {
		return nil, fmt.Errorf("token format error: %s", err.Error())
	}

	decryptedToken, err := hHandler.info.DecryptStr(encryptedToken)
	if err != nil {
		return nil, err
	}

	var token Token

	err = json.Unmarshal(decryptedToken, &token)
	if err != nil {
		return nil, fmt.Errorf("token deserialization error: %s", err.Error())
	}

	return &token, nil
}

// GetUser returns TUser struct for given `user`
func (hHandler *Handler) GetUser(user string) (info.TUser, error) {
	vUser, err := hHandler.info.GetUser(user)
	return *vUser, err
}

// CreateInfo new secret
func (hHandler *Handler) CreateInfo(ctx context.Context, hInfo TInfo) (uuid.UUID, error) {
	data, err := base64.StdEncoding.DecodeString(hInfo.DataBase64)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("data format error: %s", err.Error())
	}

	vInfo := info.TInfo{
		FileID:    hInfo.FileID,
		Name:      hInfo.Name,
		Descr:     hInfo.Descr,
		Size:      hInfo.Size,
		IsFile:    hInfo.IsFile,
		CreatedAt: hInfo.CreatedAt,
		DeleteAt:  hInfo.DeleteAt,
		Data:      data,
	}

	id, err := hHandler.info.CreateInfo(ctx, vInfo)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("error when creating: %w", err)
	}

	return id, nil
}

// StatInfo show information about secret
func (hHandler *Handler) StatInfo(ctx context.Context, fileID uuid.UUID) (TInfo, error) {
	vInfo, err := hHandler.info.StatInfo(ctx, fileID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TInfo{}, ErrInfoNotFound
		}

		return TInfo{}, fmt.Errorf("error when reading: %w", err)
	}

	hInfo := TInfo{
		FileID:     vInfo.FileID,
		Name:       vInfo.Name,
		Descr:      vInfo.Descr,
		Size:       vInfo.Size,
		IsFile:     vInfo.IsFile,
		CreatedAt:  vInfo.CreatedAt,
		DeleteAt:   vInfo.DeleteAt,
		DataBase64: base64.StdEncoding.EncodeToString(vInfo.Data),
	}

	return hInfo, nil
}

// ReadInfo show secret
func (hHandler *Handler) ReadInfo(ctx context.Context, fileID uuid.UUID) (TInfo, error) {
	vInfo, err := hHandler.info.ReadInfo(ctx, fileID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return TInfo{}, ErrInfoNotFound
		}

		return TInfo{}, fmt.Errorf("error when deleting: %w", err)
	}

	return TInfo{
		FileID:     vInfo.FileID,
		Name:       vInfo.Name,
		Descr:      vInfo.Descr,
		Size:       vInfo.Size,
		IsFile:     vInfo.IsFile,
		CreatedAt:  vInfo.CreatedAt,
		DeleteAt:   vInfo.DeleteAt,
		DataBase64: base64.StdEncoding.EncodeToString(vInfo.Data),
	}, nil
}

// ListInfo show information about all secrets
func (hHandler *Handler) ListInfo(ctx context.Context) (chan TInfo, error) {
	chIn, err := hHandler.info.ListInfo(ctx)
	if err != nil {
		return nil, err
	}

	chOut := make(chan TInfo, 100)

	go func() {
		defer close(chOut)

		for {
			select {
			case <-ctx.Done():
				return
			case vInfo, ok := <-chIn:
				if !ok {
					return
				}
				chOut <- TInfo{
					FileID:     vInfo.FileID,
					Name:       vInfo.Name,
					Descr:      vInfo.Descr,
					Size:       vInfo.Size,
					IsFile:     vInfo.IsFile,
					CreatedAt:  vInfo.CreatedAt,
					DeleteAt:   vInfo.DeleteAt,
					DataBase64: base64.StdEncoding.EncodeToString(vInfo.Data),
				}
			}
		}
	}()

	return chOut, nil
}
