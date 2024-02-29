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
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
-----END OPENSSH PRIVATE KEY-----
`
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
