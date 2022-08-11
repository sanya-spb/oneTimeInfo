package info

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/secretbox"
)

type TInfo struct {
	FileID    uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Descr     string    `json:"descr"`
	Size      int       `json:"size"`
	IsFile    bool      `json:"as_file"`
	CreatedAt time.Time `json:"created_at"`
	DeleteAt  time.Time `json:"delete_at"`
	Data      []byte    `json:"data"`
}

type TUser struct {
	Login    string // user's login
	Password string // user's password
	UID      uint   // user's ID
	GID      uint   // user's group ID
}

type Token struct {
	Status    string    `json:"status"`
	UID       uint      `json:"uid"`
	GID       uint      `json:"gid"`
	FileID    uuid.UUID `json:"file"`
	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`
}

type IStore interface {
	CreateInfo(ctx context.Context, data TInfo) (uuid.UUID, error)
	ReadInfo(ctx context.Context, fileID uuid.UUID) (*TInfo, error)
	DeleteInfo(ctx context.Context, fileID uuid.UUID) error
	CheckCredentials(login string, password string) (bool, error)
	GetUser(login string) (*TUser, error)
	ListInfo(ctx context.Context) (chan TInfo, error)
}

type Info struct {
	store     IStore   // interface to store
	secretKey [32]byte // key for encryption/decryption
}

// NewInfo - constructor
func NewInfo(secretKey [32]byte, iStore IStore) *Info {
	return &Info{
		store:     iStore,
		secretKey: secretKey,
	}
}

// CheckCredentials check if user exist with given login and password
func (info *Info) CheckCredentials(login string, password string) (bool, error) {
	return info.store.CheckCredentials(login, password)
}

// GetUser get user information by `login`
func (info *Info) GetUser(login string) (*TUser, error) {
	return info.store.GetUser(login)
}

// CreateInfo new secret and return it UUID
func (info *Info) CreateInfo(ctx context.Context, data TInfo) (uuid.UUID, error) {
	var err error

	data.FileID = uuid.New()

	data.Data, err = info.EncryptStr(data.Data)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("encrypt data error: %w", err)
	}

	_, err = info.store.CreateInfo(ctx, data)
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("create data error: %w", err)
	}

	return data.FileID, nil
}

// ReadInfo get secret by UUID
func (info *Info) ReadInfo(ctx context.Context, fileID uuid.UUID) (*TInfo, error) {
	data, err := info.store.ReadInfo(ctx, fileID)
	if err != nil {
		return nil, fmt.Errorf("read data error: %w", err)
	}

	data.Data, err = info.DecryptStr(data.Data)
	if err != nil {
		return nil, fmt.Errorf("decrypt data error: %w", err)
	}

	err = info.store.DeleteInfo(ctx, fileID)
	if err != nil {
		return nil, fmt.Errorf("delete data error: %w", err)
	}

	return data, nil
}

// StatInfo get information about secret by UUID
func (info *Info) StatInfo(ctx context.Context, fileID uuid.UUID) (*TInfo, error) {
	data, err := info.store.ReadInfo(ctx, fileID)
	if err != nil {
		return nil, fmt.Errorf("read data error: %w", err)
	}

	data.Data = nil

	return data, nil
}

// ListInfo get information about all secrets
func (info *Info) ListInfo(ctx context.Context) (chan TInfo, error) {
	chIn, err := info.store.ListInfo(ctx)
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
			case data, ok := <-chIn:
				if !ok {
					return
				}

				data.Data = nil

				chOut <- data
			}
		}
	}()

	return chOut, nil
}

// EncryptStr encrypt byte-string
func (info *Info) EncryptStr(str []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, fmt.Errorf("rand generator error: %s", err.Error())
	}

	return secretbox.Seal(nonce[:], str, &nonce, &info.secretKey), nil
}

// DecryptStr decrypt byte-string
func (info *Info) DecryptStr(encryptedStr []byte) ([]byte, error) {
	if !(len(encryptedStr) > 24) {
		return nil, errors.New("data format error")
	}

	var nonce [24]byte

	copy(nonce[:], encryptedStr[:24])

	decrypted, ok := secretbox.Open(nil, encryptedStr[24:], &nonce, &info.secretKey)
	if !ok {
		return nil, errors.New("data decryption error")
	}

	return decrypted, nil
}
