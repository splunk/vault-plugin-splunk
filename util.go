package splunk

import (
	"reflect"
	"regexp"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func getValue(data *framework.FieldData, op logical.Operation, key string) (interface{}, bool) {
	if raw, ok := data.GetOk(key); ok {
		return raw, true
	}
	if op == logical.CreateOperation {
		return data.Get(key), true
	}
	return nil, false
}

// nolint:deadcode,unused
func decodeValue(data *framework.FieldData, op logical.Operation, key string, v interface{}) error {
	raw, ok := getValue(data, op, key)
	if ok {
		rraw := reflect.ValueOf(raw)
		rv := reflect.ValueOf(v)
		rv.Elem().Set(rraw)
	}
	return nil
}

var indentWhitespace = regexp.MustCompile("(?m:^[ \t]*)")

func trimIndent(s string) string {
	return strings.TrimRight(indentWhitespace.ReplaceAllString(s, ""), "")
}
