package splunk

import (
	"fmt"
	"testing"

	"gotest.tools/assert"
)

func testUserService() *UserService {
	return testAPIParams().NewAPI(testContext()).AccessControl.Authentication.Users
}

func testUserParams(name string) *CreateUserOptions {
	return &CreateUserOptions{
		Name:       name,
		Email:      fmt.Sprintf("%s@example.com", name),
		Password:   "test1234",
		CreateRole: Bool(true),
		Roles:      []string{fmt.Sprintf("user-%s", name)},
	}
}

func TestUserService_Users(t *testing.T) {
	us := testUserService()

	users, _, err := us.Users()
	assert.NilError(t, err)
	assert.Equal(t, len(users), 1)
}

func TestUserService_Create(t *testing.T) {
	userSvc := testUserService()
	params := testUserParams("testuser97")

	user, _, err := userSvc.Create(params)
	defer userSvc.Delete(params.Name)
	assert.NilError(t, err)
	assert.Equal(t, user.Name, params.Name)
	assert.Equal(t, user.Content.Email, params.Email)
}

func TestUserService_Update_Email(t *testing.T) {
	userSvc := testUserService()
	params := testUserParams("testuser96")

	user, _, err := userSvc.Create(params)
	defer userSvc.Delete(params.Name)
	assert.NilError(t, err)
	assert.Equal(t, user.Name, params.Name)

	user, _, err = userSvc.Update(user.Name, &UpdateUserOptions{
		Email: "changed@example.com",
	})
	assert.NilError(t, err)
	assert.Equal(t, user.Content.Email, "changed@example.com")
}

func TestUserService_Update_Password(t *testing.T) {
	userSvc := testUserService()
	params := testUserParams("testuser99")

	user, _, err := userSvc.Create(params)
	defer userSvc.Delete(params.Name)
	assert.NilError(t, err)
	assert.Equal(t, user.Name, params.Name)

	user, _, err = userSvc.Update(user.Name, &UpdateUserOptions{
		Password: "changed1234",
	})
	assert.NilError(t, err)
}

func TestUserService_Update_MissingOldPassword(t *testing.T) {
	userSvc := testUserService()

	_, _, err := userSvc.Update(username, &UpdateUserOptions{
		Password: "changed1234",
	})
	assert.Error(t, err, "ERROR splunk: Missing old password.")
}

func TestUserService_Update_OwnPassword(t *testing.T) {
	userSvc := testUserService()

	_, _, err := userSvc.Update(username, &UpdateUserOptions{
		OldPassword: password,
		Password:    "password",
	})
	assert.NilError(t, err)
	_, _, err = userSvc.Update(username, &UpdateUserOptions{
		OldPassword: "password",
		Password:    password,
	})
	assert.NilError(t, err)
}

func TestUserService_Delete(t *testing.T) {
	userSvc := testUserService()
	params := testUserParams("testuser98")

	user, _, err := userSvc.Create(params)
	assert.NilError(t, err)
	assert.Equal(t, user.Content.Email, params.Email)

	_, _, err = userSvc.Delete(params.Name)
	assert.NilError(t, err)
}
