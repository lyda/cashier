package gitlab

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/nsheridan/cashier/server/auth"
	"github.com/nsheridan/cashier/server/config"

	gitlabapi "github.com/xanzy/go-gitlab"
	"golang.org/x/oauth2"
)

const (
	name = "gitlab"
)

// Config is an implementation of `auth.Provider` for authenticating using a
// Gitlab account.
type Config struct {
	config    *oauth2.Config
	baseurl   string
	group     string
	whitelist map[string]bool
	allusers  bool
}

// New creates a new Github provider from a configuration.
func New(c *config.Auth) (auth.Provider, error) {
	uw := make(map[string]bool)
	for _, u := range c.UsersWhitelist {
		uw[u] = true
	}
	allUsers := false
	fmt.Printf("Config: c.ProviderOpts[\"allusers\"] == \"%s\"\n",
		c.ProviderOpts["allusers"])
	if c.ProviderOpts["allusers"] == "true" {
		allUsers = true
	}
	if !allUsers && c.ProviderOpts["group"] == "" && len(uw) == 0 {
		return nil, errors.New("gitlab_opts group and the users whitelist must not be both empty if allusers isn't true")
	}
	authUrl := "https://gitlab.com/oauth/authorize"
	if c.ProviderOpts["authurl"] != "" {
		authUrl = c.ProviderOpts["authurl"]
	}
	tokenUrl := "https://gitlab.com/oauth/token"
	if c.ProviderOpts["tokenurl"] != "" {
		tokenUrl = c.ProviderOpts["tokenurl"]
	}
	baseUrl := "https://gitlab.com/api/v3/"
	if c.ProviderOpts["baseurl"] != "" {
		baseUrl = c.ProviderOpts["baseurl"]
	}
	return &Config{
		config: &oauth2.Config{
			ClientID:     c.OauthClientID,
			ClientSecret: c.OauthClientSecret,
			RedirectURL:  c.OauthCallbackURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authUrl,
				TokenURL: tokenUrl,
			},
			Scopes: []string{
				"api",
			},
		},
		group:     c.ProviderOpts["group"],
		whitelist: uw,
		allusers:  allUsers,
		baseurl:   baseUrl,
	}, nil
}

// A new oauth2 http client.
func (c *Config) newClient(token *oauth2.Token) *http.Client {
	return c.config.Client(oauth2.NoContext, token)
}

// Name returns the name of the provider.
func (c *Config) Name() string {
	return name
}

// Valid validates the oauth token.
func (c *Config) Valid(token *oauth2.Token) bool {
	fmt.Printf("In func Valid(%+v)\n", token)
	if !token.Valid() {
		fmt.Printf("Token not valid.\n")
		return false
	}
	if c.allusers {
		return true
	}
	fmt.Printf("  allusers == false\n")
	if len(c.whitelist) > 0 && !c.whitelist[c.Username(token)] {
		return false
	}
	if c.group == "" {
		// There's no group and token is valid.  Can only reach
		// here if user whitelist is set and user is in whitelist.
		return true
	}
	fmt.Printf("  group == ''\n")
	client := gitlabapi.NewOAuthClient(nil, token.AccessToken)
	client.SetBaseURL(c.baseurl)
	fmt.Printf("  client == '%+v'\n", client)
	groups, _, err := client.Groups.ListGroups(nil)
	if err != nil {
		return false
	}
	fmt.Printf("  groups == '%+v'\n", groups)
	for _, g := range groups {
		if g.Name == c.group {
			return true
		}
	}
	return false
}

// Revoke is a no-op revoke method. GitHub doesn't seem to allow token
// revocation - tokens are indefinite and there are no refresh options etc.
// Returns nil to satisfy the Provider interface.
func (c *Config) Revoke(token *oauth2.Token) error {
	return nil
}

// StartSession retrieves an authentication endpoint from Github.
func (c *Config) StartSession(state string) *auth.Session {
	return &auth.Session{
		AuthURL: c.config.AuthCodeURL(state),
	}
}

// Exchange authorizes the session and returns an access token.
func (c *Config) Exchange(code string) (*oauth2.Token, error) {
	t, err := c.config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}
	// Github tokens don't have an expiry. Set one so that the session expires
	// after a period.
	if t.Expiry.Unix() <= 0 {
		t.Expiry = time.Now().Add(1 * time.Hour)
	}
	return t, nil
}

// Username retrieves the username portion of the user's email address.
func (c *Config) Username(token *oauth2.Token) string {
	fmt.Printf("Username AccessToken = '%s'\n", token.AccessToken)
	client := gitlabapi.NewOAuthClient(nil, token.AccessToken)
	client.SetBaseURL(c.baseurl)
	fmt.Printf("Username client = '%+v'\n", client)
	u, _, err := client.Users.CurrentUser()
	if err != nil {
		fmt.Printf("Username err = '%+v'\n", err)
		return ""
	}
	fmt.Printf("Username u = '%+v'\n", u)
	return u.Username
}
