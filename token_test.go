package oneidjwtauth

import (
	"fmt"
	"testing"
)

var (
	testLoginBaseURL = "https://oauth2.eid-6.account.tencentcs.com/v1/sso/jwtp/1102878596482998272/1151383032381308928/kit/{app_type}"
	testIssuer       = "https://www.example.com"
	testPrivKey      = `
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPwlvSsvsxHHKkRFeMvrBPvfGio2TLEHBCsoZ34KBmpjrJHLpcvVQ7K3SX3bRfplWH2qPs5EI9zt+LQ6Jlr1rMj7Nh/ZlX698rShdBtsfLX5rlFyFlJrQPOLnX1d9lD1i2FWFrCYe/CwHqx8+Y25KIgci1lyU7CgQXD944+Hkqv1pmYrqZJvl12fTR3gx2fiC/iAsFEBTpdSWavleE6i3vKPdfsp+Ojs9bHcv5btkPIBLGVMV2oRGjHxZdDwRQSaHo9DwnSSv6p+S+xcdALHRLMUNonQ1R9hDFRLRt7/G8fB+4+OrA4I5hmYZWOV9zi8CJ/S57miPLLHcrMEa8fWSnAgMBAAECggEACxTl4EY1tHfnptq9BL/Yba3G/r19DyvFoSPJR7ROj0sckETyV9ICyn6AjefVytL3dZ30PRrWbFo60usnoAmLa/qE6fF58BZKZWe399mvrH8L/F47JMcSDEx39TWY4INstZb3BvDk3GF87QX9YmeL2Ft71jEasPHRfV1rpVmeNOkUEaV1hLYsf3l9AZ7Im8hN+2Aarp0m7oMdOY3QVZ5bQ4qlbYsjPT3aCaZIpHoUCmUrKuyqNQDpXqXYZ6imBgaU9SzYHROJ+etAxyef8d/DbshrZ77OkI+xO1Nq8OClqfOBLeKnT4tr1S0t31mBWE1fFf1590UKmovZ2mm+zrXD8QKBgQDpU0g5fUcWBdsOeL+I6VZwB+iQcRIid0XiKI1bB4mdS+cA3JNFszy5y8jHY+2amVZ7Wvorl3ZICaGMLJncdChz4e2yJ5icAmLpJ7RVNnFm5oqM+EcXW5mLS99d7GlauY0ORUdDytdfv0aWqFwkltMNV7Z1VY4C+O0X2wsPwIK2DwKBgQDj8wmTSF/P4q4vhl5VFHK5HR5KaTxZ09myd82Xl1MTADjV3E3MBkDUWGhnRYFmwLCmnuXuMBTdA6nLHEpDnWW6Q1Xtbmt5k1x9D8B9nwbA2Tmz9hGvN1l8MlYPt2Hu+E17Je6kMCdy5Iz1QUevXc3cR0DLZwFGRhgXAyIS8cg/6QKBgQCuswrK8MA+/xdrmIFg08VCkMlTDTZU1BVhJpfgZp5lRiWqgX1LnM6FFs44bNvE+7bDGfVimj+X5I4u1F5HsDlxuuIsmHUtqqPAi1f8zYzPTSLENkmUdaNbpu2R96dSpMe2vayEV+Y27JK/z0NeqgdQYDJfXDW+h/+N8xYvLycvhQKBgDezFW3ly3OywjlergJAIuBU2yf3mwWgHJvdZmFaWrRT449ua5wlEwZQLALAGySOhRvRzAFtwktXL9Avs33eIhNnjMGdr6lfdsQgazrG9xF8gvsUb7HO5pDQg/MHLmkER3qGBFAebCVI76CmOOwDEeB3kL+jBc60JgLJgzP53KKxAoGBANKZ9xIWiSyRICUIHwpWClizXj9dyXaHOl6INqd/Jj+1dqdizI7YoVufm6vDP0vKf467HKLwLm5mDlZr3j+j/Y/WkbZqluT8onPx4F7m5f8dJUu/OJtGBc1+OnfzyFt5xSAD0Q6NDAxDdKuKCV36znRdNbZu/WiICncDQIjaNCeQ
-----END PRIVATE KEY-----
`
)

func Test_NewConfig(t *testing.T) {
	_, err := NewConfig(testLoginBaseURL, testIssuer, testPrivKey)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_NewTokenWithUserinfo(t *testing.T) {
	c, _ := NewConfig(testLoginBaseURL, testIssuer, testPrivKey)
	tok, err := c.NewToken(Userinfo{
		ID:                "f99530d4-8317-4900-bd02-0127bb8c44de",
		Name:              "张三",
		PreferredUsername: "zhangsan",
		Email:             "zhangsan@example.com",
		Mobile:            "+86 13411112222",
		Extension: map[string]any{
			"picture": "https://www.example.com/avatar1.png",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if tok == "" {
		t.Fail()
	}
	// fmt.Println(tok)
}

func Test_NewTokenWithClaims(t *testing.T) {
	c, _ := NewConfig(testLoginBaseURL, testIssuer, testPrivKey)
	claims := map[string]any{
		"id":      "f99530d4-8317-4900-bd02-0127bb8c44de",
		"name":    "张三",
		"gonghao": "123456",
		"email":   "zhangsan@example.com",
		"phone":   "+86 13411112222",
	}
	tok, err := c.NewTokenWithClaims(claims)
	if err != nil {
		t.Fatal(err)
	}

	if tok == "" {
		t.Fail()
	}
	// fmt.Println(tok)
}

func Test_NewLoginURL(t *testing.T) {
	c, _ := NewConfig(testLoginBaseURL, testIssuer, testPrivKey)
	u, err := c.NewLoginURL(Userinfo{
		ID:                "f99530d4-8317-4900-bd02-0127bb8c44de",
		Name:              "张三",
		PreferredUsername: "zhangsan",
		Email:             "zhangsan@example.com",
		Mobile:            "+86 13411112222",
		Extension: map[string]any{
			"picture": "https://www.example.com/avatar1.png",
		},
	}, AppTencentMeeting)
	if err != nil {
		t.Fatal(err)
	}

	if u == "" {
		t.Fail()
	}
	fmt.Println(u)
}

func Test_NewLoginURLWithClaims(t *testing.T) {
	c, _ := NewConfig(testLoginBaseURL, testIssuer, testPrivKey)
	u, err := c.NewLoginURLWithClaims(
		map[string]any{
			"id":      "f99530d4-8317-4900-bd02-0127bb8c44de",
			"name":    "张三",
			"gonghao": "123456",
			"email":   "zhangsan@example.com",
			"phone":   "+86 13411112222",
		}, AppTencentMeeting)
	if err != nil {
		t.Fatal(err)
	}

	if u == "" {
		t.Fail()
	}
	fmt.Println(u)
}

func Test_CreateTokenWithOpenSSHKey(t *testing.T) {
	opensshKey := `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAsvOMPaO0elNzFjp/QwKCxfuWPzSqDPscpyzwW9neYwSPWrcMjIRq
RZT9xp8ufD+17XWxRk/kRts5ooYONU9qXhMx9qi2qoxjNAgT2f29eRBDCqC07aq1NqCyIV
ZihT9o3rHfRFSf21Ue8ivOuoko/W+uk0dRO/aT8cBrSTSolHXi1SCU6RSFm1xMrrUIX7oN
R5cJVjqZtIWgtRG/apK7LAOBD3B2ZcbqDHczAnjiw8tuJdlkz8GzZE22X8MJvk2u/ERA4c
6HfdtBS5jVuaKKx9UBkxxSCvi2iUuON2iQ1HJQJlNHOc5nPkWcMH8RvqaOCaQNy56Lg0NS
SdKVmi8RtuTUS866NkmVQU+DEfoXaFcaO0nj9S94jp2dfLQb708mRPJSp4RJriPYBLToQ1
C4punOot732VWadkoc4bNKh2nyPkTFEdoZj/D8H5uIL3x8tbnBbjNhfxmTUockynM78i2V
TZ7r8+tOmcdgjGZenXsBVS5AKWcPNOMrSNlMwOVbAAAFiOjgFRjo4BUYAAAAB3NzaC1yc2
EAAAGBALLzjD2jtHpTcxY6f0MCgsX7lj80qgz7HKcs8FvZ3mMEj1q3DIyEakWU/cafLnw/
te11sUZP5EbbOaKGDjVPal4TMfaotqqMYzQIE9n9vXkQQwqgtO2qtTagsiFWYoU/aN6x30
RUn9tVHvIrzrqJKP1vrpNHUTv2k/HAa0k0qJR14tUglOkUhZtcTK61CF+6DUeXCVY6mbSF
oLURv2qSuywDgQ9wdmXG6gx3MwJ44sPLbiXZZM/Bs2RNtl/DCb5NrvxEQOHOh33bQUuY1b
miisfVAZMcUgr4tolLjjdokNRyUCZTRznOZz5FnDB/Eb6mjgmkDcuei4NDUknSlZovEbbk
1EvOujZJlUFPgxH6F2hXGjtJ4/UveI6dnXy0G+9PJkTyUqeESa4j2AS06ENQuKbpzqLe99
lVmnZKHOGzSodp8j5ExRHaGY/w/B+biC98fLW5wW4zYX8Zk1KHJMpzO/ItlU2e6/PrTpnH
YIxmXp17AVUuQClnDzTjK0jZTMDlWwAAAAMBAAEAAAGBAJop3JhBjrqPZ6cvr/D/mb+L9S
zwZssWDeIrgcnvUHmHNSSWa5YmgRL+vv28pqRdkpJGgPks3GD6fZV43Yapqt3utW1kfTFC
DjiF+Owkf3VrQAZI2nWhScoM+EhmDivyq5qmK8zHBoxCsY05ljf277wd2YyBtQbubxemiA
ah+dUkFc076208w7lK87jStqsZMlWJVX7WrxHoyMEU0A206NCLGEU/wo/9pCYnDmfD0r+Q
Yozy0rl0iuIPXNz0vlEWxAcYnpb6mtcYdmCQWqUCLKhzW+S+tu2uP8q6VGQfT939Dnryqq
vrjc+TXtAH3GMBDImT2jZZSFLdXcRYAtcHBX5R3/6+aBEcfeXjzUgGeU/gdEtpFNa0RxYs
/0TJzbYbg2KWTFCIsgxrePHsnrDTOnK4M6gxJOW8VFyIgdB36d7DdfOrwJu52K+e+6XBbO
2B/8okBQoIwFhX+UmtGz5DQJseyR1ByGv0oqyRu0kFQHzpGrIqLp/FSR+yH+g1znoa4QAA
AMA+keOUyno0rJuzwUhK2RPqYRdjlD4Ba5rUpiVhgWVpA1Wp6VXtqUVNTz1poYGZEe3zwg
vyJVXC2bjbbUbzJKrTrjARXSFA2gfzF0iuVcWMbITsR7DHmX6cwGnoiHRI8Z3aNDcVMnv3
Ba3L0Bx8BddWVJGjXIfMtAow4af1VJ90H2F4cOh5QonWgBH1ZVX4/aYHKv2BL3tsedMCTE
I8k0snzTL0L/zF+QQPiamC1d/iAIIaY9moh6+Px+4610GLTrwAAADBANxnVevNkd4rO+Qa
1U/ZjSCQnwi1a1OS2+UtM9COPh+tPL0Y6HmpsNmGfk9LmN5CiC0PxK7QckCIO28Ta2OLrP
Fv3Tl4NQuJraOxbMqlezRnnODP6fLXjU4/6n/uhtmjfvgbEJt8pS5yQ/GkH3eQ5x8YDMUz
CbXcZn96r8EOa8PStAwaOb25tJM+kzEjl09K01U7sWVduevHF2GCf/ccrWwYUu/DwzzP9B
n1DJMvVy0gARwxo+rbX65vBnnryqCzqwAAAMEAz9paVC31VJXPmJX8pxWr2Q/1TPk5MV+Q
GjjUAjiBGpicV1zCe8r7CYQu4aD2s/Ud7BEHV5SbDs5LJkLpYLis1Aq9T7ZB6r73Uz918F
QClukU+/6LMn8tdEPK+9LlsM8w2wznP8ZbCL1LFappV9TJyB8QlV5/ihLguF1u7X+u4jfe
26GQGLP0qFxxjWYPKRCBeGE6esEfKWZ9sXt0nZYyGs4cbaGaQSEsMvIi9GbTs8OA+xqKvg
W4pxu7YpnZF+URAAAAEWZlbmd4aUBGRU5HWEktTUIwAQ==
-----END OPENSSH PRIVATE KEY-----`
	c, _ := NewConfig(testLoginBaseURL, testIssuer, opensshKey)
	claims := map[string]any{
		"id":      "f99530d4-8317-4900-bd02-0127bb8c44de",
		"name":    "张三",
		"gonghao": "123456",
		"email":   "zhangsan@example.com",
		"phone":   "+86 13411112222",
	}
	tok, err := c.NewTokenWithClaims(claims)
	if err != nil {
		t.Fatal(err)
	}

	if tok == "" {
		t.Fail()
	}
	fmt.Println(tok)
}
