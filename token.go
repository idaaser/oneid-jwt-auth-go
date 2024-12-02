package oneidjwtauth

import (
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
)

// Signer config
type Signer struct {
	privateKey any

	loginBaseURL string

	issuer string

	tokenLifetime int // seconds
	tokenKey      string
}

// NewSigner 初始化jwt认证源配置
func NewSigner(loginBaseURL, issuer string, privateKey string, options ...func(*Signer)) (*Signer, error) {
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

	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, errors.New("issuer MUST NOT be empty")
	}

	c := defaultConfig()
	c.privateKey = parsed
	c.loginBaseURL = loginBaseURL
	c.issuer = issuer

	for _, opt := range options {
		opt(&c)
	}

	return &c, nil
}

// NewSignerWithKeyFile 初始化jwt认证源配置, 从私钥文件中加载key
func NewSignerWithKeyFile(loginBaseURL, issuer string, keyFile string, options ...func(*Signer)) (*Signer, error) {
	b, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	return NewSigner(loginBaseURL, issuer, string(b), options...)
}

const (
	defaultTokenLifetime    = 300 // 5 minutes
	allowedMaxTokenLifetime = 300 // 1 hour
	defaultTokenParam       = "id_token"
)

func defaultConfig() Signer {
	return Signer{
		tokenLifetime: defaultTokenLifetime,
		tokenKey:      defaultTokenParam,
	}
}

/**
func WithTokenParam(param string) func(*Signer) {
	return func(c *Signer) {
		if param = strings.TrimSpace(param); param == "" {
			c.tokenKey = defaultTokenParam
			return
		}
		c.tokenKey = param
	}
}
*/

// WithTokenLifetime 设置id_token的有效期, 单位为秒
func WithTokenLifetime(sec int) func(*Signer) {
	return func(c *Signer) {
		if sec < 0 || sec > allowedMaxTokenLifetime {
			c.tokenLifetime = defaultTokenLifetime
			return
		}
		c.tokenLifetime = sec
	}
}

// NewToken 基于用户信息, 生成一个新的id_token
func (c Signer) NewToken(user Userinfo) (string, error) {
	if err := user.validate(); err != nil {
		return "", err
	}

	return c.newTokenWithClaims(user.asClaims())
}

// newTokenWithClaims 基于自定义的claims, 生成一个新的id_token
func (c Signer) newTokenWithClaims(claims map[string]any) (string, error) {
	if len(claims) == 0 {
		return "", errors.New("claims MUST NOT be empty")
	}

	t := jwt.New()

	for k, v := range claims {
		if err := t.Set(k, v); err != nil {
			return "", err
		}
	}

	// 写入其他内置字段
	if err := t.Set(openid.IssuerKey, c.issuer); err != nil {
		return "", err
	}

	// time related
	now := time.Now()
	exp := now.Add(time.Second * time.Duration(c.tokenLifetime))
	if err := t.Set(openid.IssuedAtKey, now.Unix()); err != nil {
		return "", err
	}
	if err := t.Set(openid.ExpirationKey, exp.Unix()); err != nil {
		return "", err
	}

	// set token id as jti claim
	rid, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	ridBytes, _ := rid.MarshalBinary()
	err = t.Set(openid.JwtIDKey, hex.EncodeToString(ridBytes))
	if err != nil {
		return "", err
	}

	if err = t.Set(openid.AudienceKey, AppTencentOneID); err != nil {
		return "", err
	}

	signed, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, c.privateKey))
	if err != nil {
		return "", err
	}

	return string(signed), nil
}

// NewLoginURL 给用户创建一个免登应用的url
// user表示用户信息, app代表要免登的应用(目前支持的应用见app.go)
// params表示自定义的key/value键值对(以query param的方式追加到免登链接之后)
func (c Signer) NewLoginURL(user Userinfo, app string, params ...string) (string, error) {
	tok, err := c.NewToken(user)
	if err != nil {
		return "", err
	}

	return c.newLoginURLWithToken(tok, app, params...)
}

// NewLoginURLWithClaims 给用户创建一个免登应用的url
func (c Signer) NewLoginURLWithClaims(claims map[string]any, app string, params ...string) (string, error) {
	tok, err := c.newTokenWithClaims(claims)
	if err != nil {
		return "", err
	}

	return c.newLoginURLWithToken(tok, app, params...)
}

func (c Signer) newLoginURLWithToken(tok string, app string, params ...string) (string, error) {
	if tok == "" {
		return "", errors.New("token MUST NOT be empty")
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

	q.Set(c.tokenKey, tok)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// Userinfo 代表用户信息
type Userinfo struct {
	ID string // 必填: 用户唯一标识, 映射到id_token中的sub

	Name string // 必须填写: 用户显示名, 映射到id_token中的name

	Username string // 建议填写: 登录名, 映射到id_token中的preferred_username

	Email string // 选填: 映射到id_token中的email, 映射到id_token中的email

	Mobile string // 选填: 登录名、邮箱、手机号建议三选一, 映射到id_token中的phone_number

	Extension map[string]any // 其他需要放到token里的属性
}

func (u Userinfo) validate() error {
	trim := strings.TrimSpace
	if trim(u.ID) == "" {
		return errors.New("id MUST NOT be empty")
	}

	if trim(u.Name) == "" {
		return errors.New("name MUST NOT be empty")
	}

	// 三者不能全为空
	if trim(u.Username) == "" &&
		trim(u.Email) == "" &&
		trim(u.Mobile) == "" {
		return errors.New("username/email/mobile MUST NOT all empty")
	}

	return nil
}

// asClaims 把用户信息转换为id_token的claims
func (u Userinfo) asClaims() map[string]any {
	claims := map[string]any{}
	for k, v := range u.Extension {
		claims[k] = v
	}

	// standard claims
	setter := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			claims[k] = v
		}
	}
	setter(openid.SubjectKey, u.ID)
	setter(openid.NameKey, u.Name)
	setter(openid.PreferredUsernameKey, u.Username)
	setter(openid.EmailKey, u.Email)
	setter(openid.PhoneNumberKey, u.Mobile)

	return claims
}
