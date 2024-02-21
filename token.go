package oneidjwtauth

import (
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

type Config struct {
	privateKey any

	loginBaseURL string

	issuer string

	tokenLifetime int // seconds
	tokenParam    string
}

func NewConfig(loginBaseURL string, privateKey string, options ...func(*Config)) (*Config, error) {
	parsed, err := parseRSAPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	loginBaseURL = strings.TrimSpace(loginBaseURL)
	if loginBaseURL == "" {
		return nil, errors.New("login base url MUST NOT be empty")
	}
	_, err = url.Parse(loginBaseURL)
	if err != nil {
		return nil, err
	}

	c := defaultConfig()
	c.privateKey = parsed
	c.loginBaseURL = loginBaseURL

	for _, opt := range options {
		opt(&c)
	}

	return &c, nil
}

const (
	defaultTokenLifetime    = 300  // 5 minutes
	allowedMaxTokenLifetime = 3600 // 1 hour
	defaultTokenParam       = "id_token"
)

func defaultConfig() Config {
	return Config{
		tokenLifetime: defaultTokenLifetime,
		tokenParam:    defaultTokenParam,
	}
}

func WithIssuer(iss string) func(*Config) {
	return func(c *Config) {
		c.issuer = iss
	}
}

func WithTokenParam(param string) func(*Config) {
	return func(c *Config) {
		if param = strings.TrimSpace(param); param == "" {
			c.tokenParam = defaultTokenParam
			return
		}
		c.tokenParam = param
	}
}

func WithTokenLifetime(sec int) func(*Config) {
	return func(c *Config) {
		if sec <= 0 || sec > allowedMaxTokenLifetime {
			c.tokenLifetime = defaultTokenLifetime
			return
		}
		c.tokenLifetime = sec
	}
}

// NewToken 基于用户信息, 生成一个新的id_token
func (c Config) NewToken(user Userinfo) (string, error) {
	if err := user.validate(); err != nil {
		return "", err
	}

	t := openid.New()

	// 写入其他扩展字段
	for k, v := range user.Extension {
		if err := t.Set(k, v); err != nil {
			return "", err
		}
	}

	setter := func(claim, value string) {
		if s := strings.TrimSpace(value); s != "" {
			_ = t.Set(claim, s)
		}
	}

	// 写入其他内置字段
	setter(openid.IssuerKey, c.issuer)

	// userinfo claim
	setter(openid.SubjectKey, user.ID)
	setter(openid.NameKey, user.Name)
	setter(openid.PreferredUsernameKey, user.PreferredUsername)
	setter(openid.EmailKey, user.Email)
	setter(openid.PhoneNumberKey, user.Mobile)

	// time releated
	now := time.Now()
	exp := now.Add(time.Second * time.Duration(c.tokenLifetime))
	if err := t.Set(openid.IssuedAtKey, now.Unix()); err != nil {
		return "", err
	}
	if err := t.Set(openid.ExpirationKey, exp.Unix()); err != nil {
		return "", err
	}

	signed, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, c.privateKey))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

// NewLoginURL 给用户创建一个免登应用的url
func (c Config) NewLoginURL(user Userinfo, app string, params ...string) (string, error) {
	tok, err := c.NewToken(user)
	if err != nil {
		return "", err
	}

	s := strings.ReplaceAll(c.loginBaseURL, `{app_type}`, app)
	u, _ := url.Parse(s)
	q := u.Query()

	l := len(params)
	if l%2 == 0 {
		for i := 0; i < l; i += 2 {
			if param, val := params[i], params[i+1]; param != "" && val != "" {
				q.Set(param, val)
			}
		}
	}

	q.Set(c.tokenParam, tok)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// Userinfo 代表用户信息
type Userinfo struct {
	ID string // 必填: 用户唯一标识, 映射到id_token中的sub

	Name string // 建议填写: 用户显示名

	PreferredUsername string // 建议填写: 登录名

	Email string // 选填: 映射到id_token中的email

	Mobile string // 选填: 登录名、邮箱、手机号建议三选一

	Extension map[string]any // 其他需要放到token里的属性
}

func (u Userinfo) validate() error {
	trim := strings.TrimSpace
	if trim(u.ID) == "" {
		return errors.New("id MUST NOT be empty")
	}

	// 三者不能全为空
	if trim(u.PreferredUsername) == "" &&
		trim(u.Email) == "" &&
		trim(u.Mobile) == "" {
		return errors.New("preferred_username/email/mobile MUST NOT all empty")
	}

	return nil
}
