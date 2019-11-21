package splunk

// DeploymentService encapsulates the Deployment portion of the Splunk API
type DeploymentService struct {
	client *Client
}

func newDeploymentService(client *Client) *DeploymentService {
	return &DeploymentService{
		client: client,
	}
}

// GetSearchPeers returns information about all search peers
func (d *DeploymentService) GetSearchPeers() ([]ServerInfoEntry, *Response, error) {
	info := make([]ServerInfoEntry, 0)
	resp, err := Receive(d.client.New().Get("search/distributed/peers"), &info)
	return info, resp, err
}
