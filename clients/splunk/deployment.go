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

var (
	ServerInfoEntryFilterDefault *PaginationFilter

	ServerInfoEntryFilterMinimal *PaginationFilter = &PaginationFilter{
		Filter: []string{"host", "host_fqdn", "server_roles"},
	}
)

// SearchPeers returns information about all search peers
func (d *DeploymentService) SearchPeers(filter *PaginationFilter) ([]ServerInfoEntry, *Response, error) {
	var info []ServerInfoEntry
	sling := d.client.New().Get("search/distributed/peers")
	if filter != ServerInfoEntryFilterDefault {
		sling = sling.QueryStruct(filter)
	}
	resp, err := Receive(sling, &info)
	return info, resp, err
}
