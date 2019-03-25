package splunk

import (
	"fmt"
	"strconv"
	"time"
)

// The Timestamp type is used for (un)marshalling Unix timestamps from JSON.
type Timestamp time.Time

// MarshalJSON marshals Timestamp structs to JSON.
func (t *Timestamp) MarshalJSON() ([]byte, error) {
	ts := time.Time(*t).Unix()
	stamp := fmt.Sprint(ts)

	return []byte(stamp), nil
}

// UnmarshalJSON unmarshals Timestamp structs from JSON.
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	ts, err := strconv.Atoi(string(b))
	if err != nil {
		return err
	}

	*t = Timestamp(time.Unix(int64(ts), 0))

	return nil
}
