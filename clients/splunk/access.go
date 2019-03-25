package splunk

// AccessControlService encapsulates the Access Control portion of the Splunk API.
type AccessControlService struct {
	client         *Client
	Authentication *AuthenticationService
}

func newAccessControlService(client *Client) *AccessControlService {
	return &AccessControlService{
		client:         client,
		Authentication: newAuthenticationService(client.New()),
	}
}
