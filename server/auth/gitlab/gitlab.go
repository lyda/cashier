package gitlab

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

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
	level     int
	whitelist map[string]bool
	allusers  bool
}

var levelMap = map[string]int{
	"guest":     10,
	"reporter":  20,
	"developer": 30,
	"master":    40,
	"owner":     50,
}

// New creates a new Gitlab provider from a configuration.
func New(c *config.Auth) (auth.Provider, error) {
	uw := make(map[string]bool)
	for _, u := range c.UsersWhitelist {
		uw[u] = true
	}
	allUsers := false
	if c.ProviderOpts["allusers"] == "true" {
		allUsers = true
	}
	if !allUsers && c.ProviderOpts["group"] == "" && len(uw) == 0 {
		return nil, errors.New("gitlab_opts group and the users whitelist must not be both empty if allusers isn't true")
	}
	siteUrl := "https://gitlab.com/"
	if c.ProviderOpts["siteurl"] != "" {
		siteUrl = c.ProviderOpts["siteurl"]
		if siteUrl[len(siteUrl)-1] != '/' {
			return nil, errors.New("gitlab_opts siteurl must end in /")
		}
	}
	levelOpt := 0
	if c.ProviderOpts["level"] != "" {
		levelOpt = levelMap[c.ProviderOpts["level"]]
		if levelOpt == 0 {
			var err error
			if levelOpt, err = strconv.Atoi(c.ProviderOpts["level"]); err != nil {
				return nil, errors.New("gitlab_opts level unrecognised; must be number or text level")
			}
		}
	}
	return &Config{
		config: &oauth2.Config{
			ClientID:     c.OauthClientID,
			ClientSecret: c.OauthClientSecret,
			RedirectURL:  c.OauthCallbackURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  siteUrl + "oauth/authorize",
				TokenURL: siteUrl + "oauth/token",
			},
			Scopes: []string{
				"api",
			},
		},
		group:     c.ProviderOpts["group"],
		level:     levelOpt,
		whitelist: uw,
		allusers:  allUsers,
		baseurl:   siteUrl + "api/v3/",
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
	if !token.Valid() {
		return false
	}
	if c.allusers {
		return true
	}
	if len(c.whitelist) > 0 && !c.whitelist[c.Username(token)] {
		return false
	}
	if c.group == "" {
		// There's no group and token is valid.  Can only reach
		// here if user whitelist is set and user is in whitelist.
		return true
	}
	client := gitlabapi.NewOAuthClient(nil, token.AccessToken)
	client.SetBaseURL(c.baseurl)
	groups, response, err := client.Groups.SearchGroup(c.group)
	fmt.Printf("response: %+v\n", response)
	if err != nil {
		return false
	}
	for _, g := range groups {
		fmt.Printf("group: %s = '%+v'\n", g.Path, g)
		if g.Path == c.group {
			return true
		}
	}
	return false
}

// Revoke is a no-op revoke method. Gitlab doesn't allow token
// revocation - tokens live for an hour.
// Returns nil to satisfy the Provider interface.
func (c *Config) Revoke(token *oauth2.Token) error {
	return nil
}

// StartSession retrieves an authentication endpoint from Gitlab.
func (c *Config) StartSession(state string) *auth.Session {
	return &auth.Session{
		AuthURL: c.config.AuthCodeURL(state),
	}
}

// Exchange authorizes the session and returns an access token.
func (c *Config) Exchange(code string) (*oauth2.Token, error) {
	return c.config.Exchange(oauth2.NoContext, code)
}

// Username retrieves the username of the Gitlab user.
func (c *Config) Username(token *oauth2.Token) string {
	client := gitlabapi.NewOAuthClient(nil, token.AccessToken)
	client.SetBaseURL(c.baseurl)
	u, _, err := client.Users.CurrentUser()
	if err != nil {
		return ""
	}
	return u.Username
}
