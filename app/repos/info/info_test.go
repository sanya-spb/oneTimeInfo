package info

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEncryptStr(t *testing.T) {
	var myTests = []struct {
		in struct {
			str []byte
		}
		out struct {
			str []byte
			err error
		}
	}{
		{
			in: struct {
				str []byte
			}{str: nil},
			out: struct {
				str []byte
				err error
			}{
				str: nil,
				err: nil,
			},
		},
		{
			in: struct {
				str []byte
			}{str: []byte{0x00}},
			out: struct {
				str []byte
				err error
			}{
				str: []byte{0x00},
				err: nil,
			},
		},
		{
			in: struct {
				str []byte
			}{str: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
			out: struct {
				str []byte
				err error
			}{
				str: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				err: nil,
			},
		},
	}

	ttInfo := Info{
		store:     nil,
		secretKey: [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
	}

	for _, tt := range myTests {
		encrypted, err := ttInfo.EncryptStr(tt.in.str)
		if tt.out.err != nil {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		decrypted, _ := ttInfo.DecryptStr(encrypted)
		require.Equal(t, tt.out.str, decrypted)
	}
}

func TestDecryptStr(t *testing.T) {
	var myTests = []struct {
		in struct {
			str []byte
		}
		out struct {
			str []byte
			err error
		}
	}{
		{
			in: struct {
				str []byte
			}{str: nil},
			out: struct {
				str []byte
				err error
			}{
				str: nil,
				err: nil,
			},
		},
		{
			in: struct {
				str []byte
			}{str: []byte{0x00}},
			out: struct {
				str []byte
				err error
			}{
				str: []byte{0x00},
				err: nil,
			},
		},
		{
			in: struct {
				str []byte
			}{str: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}},
			out: struct {
				str []byte
				err error
			}{
				str: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
				err: nil,
			},
		},
	}

	ttInfo := Info{
		store:     nil,
		secretKey: [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
	}

	for _, tt := range myTests {
		encrypted, _ := ttInfo.EncryptStr(tt.in.str)
		decrypted, err := ttInfo.DecryptStr(encrypted)
		if tt.out.err != nil {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		require.Equal(t, tt.out.str, decrypted)
	}
}
