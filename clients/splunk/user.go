package splunk

import (
	"net/url"
)

// UserService encapsulates the User portion of the Splunk API.
type UserService struct {
	client *Client
}

func newUserService(client *Client) *UserService {
	return &UserService{
		client: client,
	}
}

// UserEntry is returned from Users() calls.
type UserEntry struct {
	EntryMetadata
	Name    string `json:"name"`
	Content struct {
		Capabilities             []string `json:"capabilities"`
		DefaultApp               string   `json:"defaultApp"`
		DefaultAppIsUserOverride *bool    `json:"DefaultAppIsUserOverride"`
		Email                    string   `json:"email"`
		Password                 string   `json:"password"`
		RealName                 string   `json:"realname"`
		RestartBackgroundJobs    *bool    `json:"restart_background_jobs"`
		Roles                    []string `json:"roles"`
		Type                     string   `json:"type"`
		TZ                       string   `json:"tz"`
	} `json:"content"`
}

// Users returns information about all users.
func (s *UserService) Users() ([]UserEntry, *Response, error) {
	users := make([]UserEntry, 0)
	resp, err := Receive(s.client.New().Get("users"), &users)
	return users, resp, err
}

// The CreateUserOptions type provides options for creating a new user.
type CreateUserOptions struct {
	CreateRole            *bool    `url:"createrole,omitempty"`
	DefaultApp            string   `url:"defaultApp,omitempty"`
	Email                 string   `url:"email,omitempty"`
	ForceChangePass       *bool    `url:"force-change-pass,omitempty"`
	Name                  string   `url:"name"`
	Password              string   `url:"password,omitempty"`
	Realname              string   `url:"realname,omitempty"`
	RestartBackgroundJobs *bool    `url:"restart_background_jobs,omitempty"`
	Roles                 []string `url:"roles,omitempty"`
	TZ                    string   `url:"tz,omitempty"`
}

// Create creates a new user, and returns additional meta data.
func (s *UserService) Create(opts *CreateUserOptions) (*UserEntry, *Response, error) {
	users := make([]UserEntry, 0)
	resp, err := Receive(s.client.New().BodyForm(opts).Post("users"), &users)
	if err != nil || len(users) == 0 {
		return nil, resp, err
	}
	return &users[0], resp, err
}

// The UpdateUserOptions type provides options for updating a user.
type UpdateUserOptions struct {
	DefaultApp            string   `url:"defaultApp,omitempty"`
	Email                 string   `url:"email,omitempty"`
	ForceChangePass       *bool    `url:"force-change-pass,omitempty"`
	OldPassword           string   `url:"oldpassword,omitempty"`
	Password              string   `url:"password,omitempty"`
	Realname              string   `url:"realname,omitempty"`
	RestartBackgroundJobs *bool    `url:"restart_background_jobs,omitempty"`
	Roles                 []string `url:"roles,omitempty"`
	TZ                    string   `url:"tz,omitempty"`
}

// Update updates a user, and returns additional meta data.
func (s *UserService) Update(user string, opts *UpdateUserOptions) (*UserEntry, *Response, error) {
	users := make([]UserEntry, 0)
	resp, err := Receive(s.client.New().BodyForm(opts).Path("users/").Post(url.PathEscape(user)), &users)
	if err != nil || len(users) == 0 {
		return nil, resp, err
	}
	return &users[0], resp, err
}

// Delete deletes a user, and returns additional meta data.
func (s *UserService) Delete(user string) (*UserEntry, *Response, error) {
	users := make([]UserEntry, 0)
	resp, err := Receive(s.client.New().Path("users/").Delete(url.PathEscape(user)), &users)
	if err != nil || len(users) == 0 {
		return nil, resp, err
	}
	return &users[0], resp, err
}
