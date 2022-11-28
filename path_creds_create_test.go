package splunk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/splunk/vault-plugin-splunk/clients/splunk"
)

func Test_findNode(t *testing.T) {
	nodes := make([]splunk.ServerInfoEntry, 0)

	gp := filepath.Join("testdata", t.Name()+".json")
	jsonResponseSearchDistributedPeers, err := os.ReadFile(gp)
	assert.NilError(t, err)

	err = json.Unmarshal(jsonResponseSearchDistributedPeers, &nodes)
	assert.NilError(t, err)

	type args struct {
		nodeFQDN   string
		hosts      []splunk.ServerInfoEntry
		roleConfig *roleConfig
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "server entry first",
			args: args{
				nodeFQDN: "idm-i-074b0895939212e99.foo.example.com",
				hosts:    nodes,
				roleConfig: &roleConfig{
					AllowedServerRoles: []string{"*"},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "server entry last",
			args: args{
				nodeFQDN: "sh-i-0a12fdd509c2a2954.foo.example.com",
				hosts:    nodes,
				roleConfig: &roleConfig{
					AllowedServerRoles: []string{"*"},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "server entry case insensitive",
			args: args{
				nodeFQDN: "SH-I-0A12FDD509C2A2954.FOO.EXAMPLE.COM",
				hosts:    nodes,
				roleConfig: &roleConfig{
					AllowedServerRoles: []string{"*"},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "server entry short name",
			args: args{
				nodeFQDN: "SH-I-0A12FDD509C2A2954",
				hosts:    nodes,
				roleConfig: &roleConfig{
					AllowedServerRoles: []string{"*"},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "server entry not found",
			args: args{
				nodeFQDN: "unknown-host",
				hosts:    nodes,
				roleConfig: &roleConfig{
					AllowedServerRoles: []string{"*"},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "role match mismatch",
			args: args{
				nodeFQDN: "sh-i-0a12fdd509c2a2954.foo.example.com",
				hosts:    nodes,
				roleConfig: &roleConfig{
					AllowedServerRoles: []string{"unknown-role"},
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "role match first",
			args: args{
				nodeFQDN: "sh-i-0a12fdd509c2a2954.foo.example.com",
				hosts:    nodes,
				roleConfig: &roleConfig{
					AllowedServerRoles: []string{"cluster_search_head"},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "role match last",
			args: args{
				nodeFQDN: "sh-i-0a12fdd509c2a2954.foo.example.com",
				hosts:    nodes,
				roleConfig: &roleConfig{
					AllowedServerRoles: []string{"unknown_role", "kv_store"},
				},
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findNode(tt.args.nodeFQDN, tt.args.hosts, tt.args.roleConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("findNode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got != nil) != tt.want {
				t.Errorf("findNode() = %v, want %v", got, tt.want)
			}
		})
	}
}
