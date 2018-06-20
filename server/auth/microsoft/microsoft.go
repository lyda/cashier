package microsoft

import (
	"errors"
	"net/http"
	"strings"

	"github.com/nsheridan/cashier/server/auth"
	"github.com/nsheridan/cashier/server/config"
	"github.com/nsheridan/cashier/server/metrics"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

//XXX: This is a work-in-progress! DO NOT USE!
// MS issue INSANELY LONG access tokens that exceed shell line length

const (
	//FIXME:
	// revokeURL = ""
	name = "microsoft"
)

// Config is an implementation of `auth.Provider` for authenticating using a
// Microsoft Azure AD account.
type Config struct {
	config    *oauth2.Config
	tenant    string
	whitelist map[string]bool
}

var _ auth.Provider = (*Config)(nil)

// New creates a new Google provider from a configuration.
func New(c *config.Auth) (*Config, error) {
	uw := make(map[string]bool)
	for _, u := range c.UsersWhitelist {
		uw[u] = true
	}
	if c.ProviderOpts["tenant"] == "" && len(uw) == 0 {
		return nil, errors.New("either AD tenant or users whitelist must be specified")
	}

	return &Config{
		config: &oauth2.Config{
			ClientID:     c.OauthClientID,
			ClientSecret: c.OauthClientSecret,
			RedirectURL:  c.OauthCallbackURL,
			Endpoint:     microsoft.AzureADEndpoint(c.ProviderOpts["tenant"]),
			Scopes:       []string{"user.Read"},
		},
		whitelist: uw,
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
	// FIXME: Validate harder
	if !token.Valid() {
		return false
	}
	metrics.M.AuthValid.WithLabelValues("microsoft").Inc()
	return true
}

// Revoke disables the access token.
func (c *Config) Revoke(token *oauth2.Token) error {
	//FIXME
	return nil
}

// StartSession retrieves an authentication endpoint from Google.
func (c *Config) StartSession(state string) *auth.Session {
	return &auth.Session{
		AuthURL: c.config.AuthCodeURL(state),
	}
}

// Exchange authorizes the session and returns an access token.
func (c *Config) Exchange(code string) (*oauth2.Token, error) {
	t, err := c.config.Exchange(oauth2.NoContext, code)
	if err == nil {
		metrics.M.AuthExchange.WithLabelValues("google").Inc()
	}
	return t, err
}

// Email retrieves the email address of the user.
func (c *Config) Email(token *oauth2.Token) string {
	// TODO: Given an access token, request the current user profile from
	// `https://graph.microsoft.com/v1.0/me`. Parse out whatever passes for an
	// email address from the response.
	return ""
}

// Username retrieves the username portion of the user's email address.
func (c *Config) Username(token *oauth2.Token) string {
	return strings.Split(c.Email(token), "@")[0]
}
