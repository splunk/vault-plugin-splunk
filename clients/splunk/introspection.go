package splunk

// IntrospectionService encapsulates the Introspection portion of the Splunk API.
type IntrospectionService struct {
	client *Client
}

func newIntrospectionService(client *Client) *IntrospectionService {
	return &IntrospectionService{
		client: client,
	}
}

// ServerInfoEntry is returned from ServerInfo() calls.
//
// BUG(mweber): this type is incomplete.
type ServerInfoEntry struct {
	EntryMetadata
	Content struct {
		ActiveLicenseGroup string `json:"activeLicenseGroup"`
		// XXX ...
		Build    string `json:"build"`
		CPUArch  string `json:"cpu_arch"`
		GUID     string `json:"guid"`
		Host     string `json:"host"`
		HostFQDN string `json:"host_fqdn"`
		IsFree   bool   `json:"isFree"`
		IsTrial  bool   `json:"isTrial"`
		// XXX ...
		Roles       []string  `json:"server_roles"`
		ServerName  string    `json:"serverName"`
		StartupTime Timestamp `json:"startup_time"`
		Version     string    `json:"version"`
	} `json:"content"`
}

// ServerInfo returns information about the Splunk instance.
func (s *IntrospectionService) ServerInfo() ([]ServerInfoEntry, *Response, error) {
	info := make([]ServerInfoEntry, 0)
	resp, err := Receive(s.client.New().Get("server/info"), &info)
	return info, resp, err
}
