package splunk

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-uuid"
	"github.com/ory/dockertest"
	"golang.org/x/oauth2"
)

const (
	testDefaultSplunkContainer = "splunk/splunk"
	testDefaultSplunkVersion   = "latest" /// XXX configurable
	testDefaultAdmin           = "admin"
	testDefaultPassword        = "test1234" // minimally satisfies Splunk password requirements
	testDefaultPort            = "8089/tcp"
)

var testGlobalSplunkConn *API

// TestMainRunner is an interface for running Tests.
//
// This interface is implemented by testing.M.
type TestMainRunner interface {
	Run() (status int)
}

func shouldRunIntegrationTests() bool {
	return !testing.Short()
}

// WithTestMainSetup provides global test setup for integration tests with Splunk.
//
// During the life-time of a test run, a Splunk container is provided, and a client,
// which is configured to access the Splunk instance.  Configuration details
// (e.g., admin user and password) can be obtained from the client.
//
// See also: TestGlobalSplunkClient
func WithTestMainSetup(runner TestMainRunner) {
	// os.Exit() prevents deferred functions from running, hence these shenanigans
	var (
		err    error
		status int
	)
	defer func() {
		if err != nil {
			log.Fatalln(err)
		}
		os.Exit(status)
	}()

	flag.Parse()
	if shouldRunIntegrationTests() {
		var (
			cleanup func()
			conn    *API
		)
		log.Print("starting new service...")
		cleanup, conn, err = NewTestSplunkServiceWithTempAdmin()
		defer cleanup()
		if err != nil {
			return
		}
		log.Printf("using Splunk service at %s", conn.Params().BaseURL)
		testGlobalSplunkConn = conn
	}
	status = runner.Run()
}

// TestGlobalSplunkClient returns a Splunk API client that is configured to access a test Splunk instance.
//
// If no Splunk instance has been set up via WithTestMainSetup, the calling test is skipped.
func TestGlobalSplunkClient(t *testing.T) *API {
	t.Helper()
	if testGlobalSplunkConn == nil {
		t.SkipNow()
	}
	return testGlobalSplunkConn
}

// TestDefaultContext returns a context set up for use in a Splunk client.
//
// See also: APIParams.NewAPI
func TestDefaultContext() context.Context {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // XXX
	}
	// client is the underlying transport for API calls, including Login (for obtaining session token)
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(1) * time.Minute,
	}
	return context.WithValue(context.Background(), oauth2.HTTPClient, client)
}

// NewTestSplunkClient returns a new Splunk API client using the context provided by TestDefaultContext.
func NewTestSplunkClient(url, username, password string) *API {
	p := &APIParams{
		BaseURL: url,
		Config: oauth2.Config{
			ClientID:     username,
			ClientSecret: password,
		},
	}
	return p.NewAPI(TestDefaultContext())
}

// NewTestSplunkService spins up a new Splunk service, and returns a Splunk API configured to access it.
//
// If the SPLUNK_ADDR environment variable is set, the tests will run against the specified Splunk.
// If also the SPLUNK_PASSWORD environment variable is set, this password will be used for admin access,
// instead of a default password ("test1234").
//
// Example:
// 		export SPLUNK_ADDR='https://localhost:8089'
//      export SPLUNK_PASSWORD='SECRET'
func NewTestSplunkService() (cleanup func(), conn *API, err error) {
	cleanup = func() {}
	url := os.Getenv("SPLUNK_ADDR")
	if url != "" {
		password := os.Getenv("SPLUNK_PASSWORD")
		if password == "" {
			password = testDefaultPassword
		}
		conn = NewTestSplunkClient(url, testDefaultAdmin, password)
		return
	}
	password, err := uuid.GenerateUUID()
	if err != nil {
		err = errwrap.Wrapf("error generating password: {{err}}", err)
		return
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		err = errwrap.Wrapf("Failed to connect to docker: {{err}}", err)
		return
	}

	env := []string{
		"SPLUNK_START_ARGS=--accept-license",
		fmt.Sprintf("SPLUNK_PASSWORD=%s", password),
	}
	resource, err := pool.Run(testDefaultSplunkContainer, testDefaultSplunkVersion, env)
	if err != nil {
		err = errwrap.Wrapf("failed to start local container: {{err}}", err)
		return
	}

	cleanup = func() {
		if err := pool.Purge(resource); err != nil {
			log.Printf("failed to cleanup local container: %s", err)
		}
	}

	url = fmt.Sprintf("https://localhost:%s", resource.GetPort(testDefaultPort))
	conn = NewTestSplunkClient(url, testDefaultAdmin, password)

	// the container seems to take at least one minute to start
	pool.MaxWait = time.Duration(2) * time.Minute
	err = pool.Retry(func() error {
		_, _, err := conn.Introspection.ServerInfo()
		return err
	})
	if err != nil {
		err = errwrap.Wrapf("Could not connect to Splunk container: {{err}}", err)
		return
	}
	return
}

// NewTestSplunkServiceWithTempAdmin spins up a new Splunk instance, and also creates a new test admin user.
//
// See also: NewTestSplunkService
func NewTestSplunkServiceWithTempAdmin() (cleanup func(), conn *API, err error) {
	cleanup, conn, err = NewTestSplunkService()
	if err != nil {
		return
	}
	testUserID, _ := uuid.GenerateUUID()
	testUser := fmt.Sprintf("test-admin-%s", testUserID)
	testPass, _ := uuid.GenerateUUID()
	_, _, err = conn.AccessControl.Authentication.Users.Create(&CreateUserOptions{
		Name:     testUser,
		Password: testPass,
		Roles:    []string{"admin"},
	})
	if err != nil {
		err = errwrap.Wrapf(fmt.Sprintf("unable to create test user %q: {{err}}", testUser), err)
		return
	}

	clConn := conn
	clCleanup := cleanup
	cleanup = func() {
		clConn.AccessControl.Authentication.Users.Delete(testUser)
		clCleanup()
	}
	// switch to test (admin) user
	conn = NewTestSplunkClient(conn.Params().BaseURL, testUser, testPass)
	return
}
