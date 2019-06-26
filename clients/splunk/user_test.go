package splunk

import (
	"fmt"
	"log"
	"testing"

	"github.com/hashicorp/go-uuid"

	"gotest.tools/assert"
)

const defaultAdminUser = "admin"

func TestUserService_Users(t *testing.T) {
	us := testUserService(t)

	users, _, err := us.Users()
	assert.NilError(t, err)
	for ii := range users {
		if users[ii].Name == defaultAdminUser {
			return
		}
	}
	t.Fail()
}

func TestUserService_Create(t *testing.T) {
	userSvc := testUserService(t)
	params := testUserParams("")

	user, _, err := userSvc.Create(params)
	assert.NilError(t, err)
	// nolint:errcheck
	defer userSvc.Delete(user.Name)
	assert.Equal(t, user.Name, params.Name)
	assert.Equal(t, user.Content.Email, params.Email)
}

func TestUserService_Delete(t *testing.T) {
	userSvc := testUserService(t)
	params := testUserParams("")

	user, _, err := userSvc.Create(params)
	assert.NilError(t, err)

	_, _, err = userSvc.Delete(user.Name)
	assert.NilError(t, err)
}

func TestUserService_Update_Email(t *testing.T) {
	userSvc := testUserService(t)
	params := testUserParams("")

	user, _, err := userSvc.Create(params)
	assert.NilError(t, err)
	// nolint:errcheck
	defer userSvc.Delete(user.Name)
	assert.Equal(t, user.Name, params.Name)

	user, _, err = userSvc.Update(user.Name, &UpdateUserOptions{
		Email: "changed@example.com",
	})
	assert.NilError(t, err)
	assert.Equal(t, user.Content.Email, "changed@example.com")
}

func TestUserService_Update_Password(t *testing.T) {
	userSvc := testUserService(t)
	params := testUserParams("")

	user, _, err := userSvc.Create(params)
	assert.NilError(t, err)
	// nolint:errcheck
	defer userSvc.Delete(user.Name)
	assert.NilError(t, err)
	assert.Equal(t, user.Name, params.Name)

	_, _, err = userSvc.Update(user.Name, &UpdateUserOptions{
		Password: "changed1234",
	})
	assert.NilError(t, err)
}

func TestUserService_Update_MissingOldPassword(t *testing.T) {
	userSvc := testUserService(t)
	self := testGlobalSplunkConn.Params().ClientID

	_, _, err := userSvc.Update(self, &UpdateUserOptions{
		Password: "changed1234",
	})
	assert.Error(t, err, "ERROR splunk: Missing old password.")
}

func TestUserService_Update_OwnPassword(t *testing.T) {
	userSvc := testUserService(t)

	params := testUserParams("")
	user, _, err := userSvc.Create(params)
	assert.NilError(t, err)
	// nolint:errcheck
	defer userSvc.Delete(user.Name)

	_, _, err = userSvc.Update(user.Name, &UpdateUserOptions{
		OldPassword: params.Password,
		Password:    "password",
	})
	assert.NilError(t, err)
}

// Helpers
func testUserService(t *testing.T) *UserService {
	return TestGlobalSplunkClient(t).AccessControl.Authentication.Users
}

func testNewUsername(prefix string) string {
	id, err := uuid.GenerateUUID()
	if err != nil {
		log.Fatal(err)
	}
	name := fmt.Sprintf("%s%s", prefix, id)
	return name
}

func testUserParams(name string) *CreateUserOptions {
	if name == "" {
		name = testNewUsername("testuser-")
	}
	return &CreateUserOptions{
		Name:       name,
		Email:      fmt.Sprintf("%s@example.com", name),
		Password:   "test1234",
		CreateRole: Bool(true),
	}
}
