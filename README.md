# oneid-jwt-auth
oneid jwt auth golang sdk

## 使用步骤

1. go.mod里引用sdk: github.com/idaaser/oneid-jwt-auth v1.0.3
2. 初始化配置: NewConfig()或 NewConfigWithKeyFile(), 参考token_test.go
3. 生成免登url: 
    - 通过用户信息Userinfo结构生成: NewLoginURLWithClaims(claimsMap, app)
    - 通过自定义claims生成: NewLoginURL(userinfo, app)
