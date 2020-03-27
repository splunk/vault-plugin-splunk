package splunk

import (
	"github.com/hashicorp/go-uuid"
	"github.com/mr-tron/base58"
)

func GenerateShortUUID(size int) (string, error) {
	bytes, err := uuid.GenerateRandomBytes(size)
	if err != nil {
		return "", err
	}
	return FormatShortUUID(bytes), nil
}

func FormatShortUUID(bytes []byte) string {
	return base58.Encode(bytes)
}
