package oneidjwtauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_NilID(t *testing.T) {
	user := Userinfo{Name: "test"}
	err := user.validate()
	assert.NotNil(t, err)
	t.Log(err.Error())
}

func Test_EmptyID(t *testing.T) {
	user := Userinfo{ID: " ", Name: "test"}
	err := user.validate()
	assert.NotNil(t, err)
	t.Log(err.Error())
}

func Test_NilName(t *testing.T) {
	user := Userinfo{ID: "id"}
	err := user.validate()
	assert.NotNil(t, err)
	t.Log(err.Error())
}

func Test_EmptyName(t *testing.T) {
	user := Userinfo{Name: " "}
	err := user.validate()
	assert.NotNil(t, err)
	t.Log(err.Error())
}

func Test_EmptyUsernameAndEmailAndMobile(t *testing.T) {
	user := Userinfo{ID: "id", Name: "test"}
	err := user.validate()
	assert.NotNil(t, err)
	t.Log(err.Error())
}
