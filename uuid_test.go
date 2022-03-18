package splunk

import (
	"fmt"
	"testing"

	"github.com/mr-tron/base58"
	"gotest.tools/v3/assert"
)

func TestGenerateShortUUID(t *testing.T) {
	for _, size := range []int{8, 16} {
		uuid, err := GenerateShortUUID(size)
		assert.NilError(t, err)
		fmt.Println(uuid)
		bytes, err := base58.Decode(uuid)
		assert.NilError(t, err)
		assert.Equal(t, size, len(bytes))
	}
}

func TestFormatShortUUID(t *testing.T) {
	type args struct {
		bytes []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "0_x_8",
			args: args{[]byte{0, 0, 0, 0, 0, 0, 0, 0}},
			want: "11111111",
		},
		{
			name: "1_x_8",
			args: args{[]byte{0, 0, 0, 0, 0, 0, 0, 1}},
			want: "11111112",
		},
		{
			name: "255_x_8",
			args: args{[]byte{255, 255, 255, 255, 255, 255, 255, 255}},
			want: "jpXCZedGfVQ",
		},
		{
			name: "uuid4",
			args: args{[]byte{0xb3, 0x3b, 0x6b, 0x76, 0xcb, 0x1f, 0xbe, 0x28, 0xbd, 0x5b, 0x86, 0xca, 0x76, 0x23, 0x72, 0x72}},
			want: "P8gD5AcMf2n6FkGz9nydEZ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatShortUUID(tt.args.bytes); got != tt.want {
				t.Errorf("FormatShortUUID() = %v, want %v", got, tt.want)
			}
		})
	}
}
