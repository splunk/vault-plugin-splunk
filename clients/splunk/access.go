package splunk

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
