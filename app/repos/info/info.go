package info

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

type TInfo struct {
	FileID     uint      `json:"id"`
	Name       string    `json:"name"`
	Descr      string    `json:"descr"`
	Size       int       `json:"size"`
	IsFile     bool      `json:"as_file"`
	CreatedAt  time.Time `json:"created_at"`
	DeleteAt   time.Time `json:"delete_at"`
	DataBase64 string    `json:"data"`
}

type TUser struct {
	Login    string
	Password string
	UID      uint
	GID      uint
}

type Token struct {
	Status    string    `json:"status"`
	UID       uint      `json:"uid"`
	GID       uint      `json:"gid"`
	FileID    uint      `json:"file"`
	ServiceID int       `json:"service"`
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
}

type InfoStore interface {
	CreateInfo(ctx context.Context, data TInfo) (uint, error)
	ReadInfo(ctx context.Context, fileID uint, serviceID int) (*TInfo, error)
	DeleteInfo(ctx context.Context, fileID uint, serviceID int) error
	CheckCredentials(login string, password string) (bool, error)
	GetUser(login string) (*TUser, error)
	GetNextFileID() (uint, error)
	ListInfo(ctx context.Context) (chan TInfo, error)
}

type Info struct {
	store     InfoStore
	secretKey [32]byte
}

func NewInfo(secretKey [32]byte, iStore InfoStore) *Info {
	return &Info{
		store:     iStore,
		secretKey: secretKey,
	}
}

func (info *Info) CheckCredentials(login string, password string) (bool, error) {
	return info.store.CheckCredentials(login, password)
}

func (info *Info) GetUser(login string) (*TUser, error) {
	return info.store.GetUser(login)
}

func (info *Info) GetNextFileID() (uint, error) {
	return info.store.GetNextFileID()
}

// Create new data with returning it UUID
func (info *Info) CreateInfo(ctx context.Context, data TInfo) (uint, error) {
	var err error

	data.FileID, err = info.GetNextFileID()
	if err != nil {
		return 0, fmt.Errorf("create data error: %w", err)
	}

	_, err = info.store.CreateInfo(ctx, data)
	if err != nil {
		return 0, fmt.Errorf("create data error: %w", err)
	}

	return data.FileID, nil
}

// Get Info by UUID
func (info *Info) ReadInfo(ctx context.Context, fileID uint, serviceID int) (*TInfo, error) {
	if serviceID != 1 {
		return nil, errors.New("unknown service")
	}

	data, err := info.store.ReadInfo(ctx, fileID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("read data error: %w", err)
	}

	err = info.store.DeleteInfo(ctx, fileID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("delete data error: %w", err)
	}

	return data, nil
}

// Get Stat by UUID
func (info *Info) StatInfo(ctx context.Context, fileID uint, serviceID int) (*TInfo, error) {
	if serviceID != 1 {
		return nil, errors.New("unknown service")
	}

	data, err := info.store.ReadInfo(ctx, fileID, serviceID)
	if err != nil {
		return nil, fmt.Errorf("read data error: %w", err)
	}
	data.DataBase64 = ""

	return data, nil
}

func (info *Info) ListInfo(ctx context.Context) (chan TInfo, error) {
	chin, err := info.store.ListInfo(ctx)
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
				data.DataBase64 = ""
				chout <- data
			}
		}
	}()

	return chout, nil
}

func (info *Info) EncryptStr(uncryptedStr []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("rand generator error: %s", err.Error())
	}

	return secretbox.Seal(nonce[:], uncryptedStr, &nonce, &info.secretKey), nil
}

func (info *Info) DecryptStr(cryptedStr []byte) ([]byte, error) {
	if !(len(cryptedStr) > 24) {
		return nil, errors.New("data format error")
	}

	var nonce [24]byte
	copy(nonce[:], cryptedStr[:24])
	decrypted, ok := secretbox.Open(nil, cryptedStr[24:], &nonce, &info.secretKey)
	if !ok {
		return nil, errors.New("data decryption error")
	}

	return decrypted, nil
}
