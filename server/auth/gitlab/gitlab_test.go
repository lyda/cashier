package gitlab

import (
	"fmt"
	"testing"

	"github.com/nsheridan/cashier/server/auth"
	"github.com/nsheridan/cashier/server/config"
	"github.com/stretchr/testify/assert"
)

var (
	oauthClientID     = "id"
	oauthClientSecret = "secret"
	oauthCallbackURL  = "url"
	authurl           = "https://exampleorg/oauth/authorize"
	tokenurl          = "https://exampleorg/oauth/token"
	group             = "exampleorg"
)

func TestNew(t *testing.T) {
	a := assert.New(t)

	p, _ := newGitlab()
	g := p.(*Config)
	a.Equal(g.config.ClientID, oauthClientID)
	a.Equal(g.config.ClientSecret, oauthClientSecret)
	a.Equal(g.config.RedirectURL, oauthCallbackURL)
}

func TestNewEmptyAuthURL(t *testing.T) {
	authurl = ""
	a := assert.New(t)

	_, err := newGitlab()
	a.EqualError(err, "gitlab_opts authurl and tokenurl must be set")

	authurl = "https://exampleorg/oauth/authorize"
}

func TestNewEmptyGroupList(t *testing.T) {
	group = ""
	a := assert.New(t)

	_, err := newGitlab()
	a.EqualError(err, "gitlab_opts group and the users whitelist must not be both empty if allusers isn't true")

	group = "exampleorg"
}

func TestStartSession(t *testing.T) {
	a := assert.New(t)

	p, _ := newGithub()
	s := p.StartSession("test_state")
	a.Contains(s.AuthURL, "exampleorg/oauth/authorize")
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", oauthClientID))
}

func newGitlab() (auth.Provider, error) {
	c := &config.Auth{
		OauthClientID:     oauthClientID,
		OauthClientSecret: oauthClientSecret,
		OauthCallbackURL:  oauthCallbackURL,
		ProviderOpts: map[string]string{
			"group":    group,
			"authurl":  authurl,
			"tokenurl": tokenurl,
		},
	}
	return New(c)
}
