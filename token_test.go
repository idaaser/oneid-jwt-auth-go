package oneidjwtauth

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testLoginBaseURL = "https://oauth2.ci-731.account.tencentcs.com/v1/sso/jwtp/1025001377618722816/1251178680399439872/kit/{app_type}"
	testIssuer       = "https://www.example.com"
	testPriKey       = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDZQ49fYR5cA4hWzVV1jVk9voaDVXwTSenqKg8EPYphjOMZIm1Lt5CMs8WaZxuG/ouBkGhLwbtPu+Sf1JPgj3Cxs8dbhXRH8k7GzEznv8b/r+F6pr9TjCgscgVd9gy7rlXdtLj425LIf3yFoXlckQNSExjuZxMP93JiaGmgJT6yXwK7bPCI8AMGLuE0M71YCIJDoDVp8NdfZYrD6giHF6RBfucNhfISizWHHUWVxc4dbBC8SjOLldq8qSJl+e/O0wpo3u/tZU2ANhuBR2tkqtpVa8Qdvg+G+OoPDINc7UiORl9M51eaVfss+wEmf+3nh2aqKpNiJOyMcJWzIkW0wc4NAgMBAAECggEADEyUyzN2QoM4rqFFGzh7OtGUT88BDR58DXOAEh9hvA/7syqNwWGM30o1/32iw0uZniYMoW1AK01ZreqczHOST5z7xiSR5pjC+OIL4Hqsy0CrpQPXhOVESO/TefQ52E4QMlLOvdfAQXVmGTKA6kqTQ4wtNyHCpH6/jO6YPCafm/1GOHTFYUbmzM185ih/0RHvnTeXmyt1Aj+3bf9wfGk3VAKLYjZHJyw+GuZTgbL16ldX4Ri16qB2Ik5ZEV7iCcATjijUJ3F/J2SCtt0kPKOiPZxQ+VOVNd6TgPN21O9CeYxyV8U66v6J0h064WMkiS63AbskfevwFmFSSc6q6q8sgQKBgQDt2jIy13Wz0w76mEaRlbjOhud4txPugaOYv+SDiHxnY7kPE7C8795Ek+JooNWjaQ8Fi/EGgWMmB5mxWjyv63HMWADe98gHvKZncqYrjF0y89yjmhJJFf1/pZYR1nJuXKVds15tdERSphp9UpaYCibjkFjh1ZZxDr+bquc8X3wgkQKBgQDp1zmCn6fYiRUE20/8CfQE8VtAKk1fKDr/j1jXZOOSEavww8IRkWXHvuVo5Hu3hKosavW9/cBiioV6ucR3de8Fmvv95VqTH6JTonGPw+Mw4vg/LRprHpuLkN2MaKoXRkQi2BSqppbqT3bfSGLsZ/xx9Rlw45u685a1pD+tvgMTvQKBgGs1gpLwExmu9H13zbcpaVeN7x+2RcGnpXngZLv09T4U8QEeuvcul10J22+VrzYs0JyLa2SnRW2K13fdWKVi1rRoplvaC8uQ+OCACO5wIkIpMTZ85+kRhGXY2T/JDWM5V0BY7SMg2Pr369C5PS/iw4ynL6j7gQgMwckEy52m3GhBAoGADvX/LvVKBteWaa4iauy0GRDcFrneI2VuiOVB+N3ylWjeCFRt+TPFQEddZB2iMLajMJ5TRKmUgnl8WsLB6Ca6eTBWSQNAjUMr3o/5FgqhYYJUAa7ADvRxXTeShSY5I64SM+yBPf3Uj/8vis+VzKxGgX/99bQKRabKEKsGi/YpOj0CgYA9qkeUVOarD8ZJ+7X4sK+dL66ICHe2ojkXI/fTxGzOU8/WlpsKHGPvlJui5awAijb3BuaWj8gReJYndSLFsg3pKWEsYc3gej5HNKfN0Pm9UuWKODoSm0uK3dUzNiQx3Wd2QxVWHa4hEPkNJ19dlcgqOJh/LxwdhRJg8kzqdsbT+w==
-----END PRIVATE KEY-----
`
	testPriKeyFile = "./private.key"
)

func Test_NewSigner(t *testing.T) {
	_, err := NewSigner(testPriKey, testIssuer, testLoginBaseURL)
	assert.NoError(t, err)
}

func Test_NewSignerWithKeyFile(t *testing.T) {
	_, err := NewSignerWithKeyFile(testPriKeyFile, testIssuer, testLoginBaseURL)
	assert.NoError(t, err)
}

func Test_NewSignerWithLifeTime(t *testing.T) {
	signer, err := NewSigner(testPriKey, testIssuer, testLoginBaseURL, WithTokenLifetime(200))
	assert.NoError(t, err)
	assert.Equal(t, 200, signer.tokenLifetime)

	_, err = NewSigner(testPriKey, testIssuer, testLoginBaseURL, WithTokenLifetime(301))
	assert.Error(t, err)
}

func Test_newToken(t *testing.T) {
	c, err := NewSigner(testPriKey, testIssuer, testLoginBaseURL)
	assert.NoError(t, err)

	tok, err := c.newToken(Userinfo{
		ID:       "f99530d4-8317-4900-bd02-0127bb8c44de",
		Name:     "张三",
		Username: "zhangsan",
		Email:    "zhangsan@example.com",
		Mobile:   "+86 13411112222",
		Extension: map[string]any{
			"picture": "https://www.example.com/avatar1.png",
		},
	})
	assert.Nil(t, err)
	assert.NotEmpty(t, tok)
	t.Log(tok)
}

func Test_NewLoginURL(t *testing.T) {
	c, err := NewSigner(testPriKey, testIssuer, testLoginBaseURL)
	assert.NoError(t, err)

	user := Userinfo{
		ID:       "f99530d4-8317-4900-bd02-0127bb8c44de",
		Name:     "张三",
		Username: "zhangsan",
		Email:    "zhangsan@example.com",
		Mobile:   "+86 13411112222",
		Extension: map[string]any{
			"picture": "https://www.example.com/avatar1.png",
		},
	}
	u, err := c.NewLoginURL(user, AppTencentMeeting)
	assert.NoError(t, err)
	assert.NotEmpty(t, u)
	fmt.Println(u)

	k := "meeting_common"
	v := "https://meeting.tencent.com"
	urlWithParam, err := c.NewLoginURL(user, AppTencentMeeting, k, v)
	assert.NoError(t, err)
	assert.NotEmpty(t, urlWithParam)

	loginURL, _ := url.Parse(urlWithParam)
	q := loginURL.Query()
	assert.NotEmpty(t, q[k])
	assert.Equal(t, v, q[k][0])
	t.Log(urlWithParam)
}

func Test_NewLoginURLWithOpenSSHKey(t *testing.T) {
	opensshKey := `-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`
	c, err := NewSigner(opensshKey, testIssuer, testLoginBaseURL)
	assert.NoError(t, err)

	u, err := c.NewLoginURL(Userinfo{
		ID:       "f99530d4-8317-4900-bd02-0127bb8c44de",
		Name:     "张三",
		Username: "zhangsan",
		Email:    "zhangsan@example.com",
		Mobile:   "+86 13411112222",
		Extension: map[string]any{
			"picture": "https://www.example.com/avatar1.png",
		},
	}, AppTencentMeeting)
	assert.NoError(t, err)
	assert.NotEmpty(t, u)
	fmt.Println(u)
}
