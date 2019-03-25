package splunk

// AuthenticationService encapsulates the Authentication portion of the Splunk API.
type AuthenticationService struct {
	client     *Client
	authClient *Client
	Users      *UserService
}

func newAuthenticationService(client *Client) *AuthenticationService {
	base := client.New().Path("authentication/")
	return &AuthenticationService{
		client:     base,
		authClient: client.New().Path("auth/"),
		Users:      newUserService(base.New()),
	}
}

type userCredentials struct {
	Username string `url:"username"`
	Password string `url:"password"`
}

// LoginResponse is returned from Login() calls.
type LoginResponse struct {
	APIError
	SessionKey string `json:"sessionKey"`
}

// Login returns a valid session key, or an error.
func (s *AuthenticationService) Login(username, password string) (*LoginResponse, error) {
	creds := userCredentials{username, password}
	apiResp := &LoginResponse{}
	apiErr := &APIError{}

	_, err := s.authClient.New().BodyForm(&creds).Post("login").Receive(apiResp, apiErr)
	if err != nil || !apiErr.Empty() { // XXX check fatal
		return nil, relevantError(err, apiErr)
	}
	return apiResp, err
}
