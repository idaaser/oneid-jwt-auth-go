# oneid-jwt-auth-go
oneid jwt auth golang sdk

## 使用步骤

1. go.mod里引用sdk: github.com/idaaser/oneid-jwt-auth v1.0.3
2. 初始化配置: NewSigner()或 NewSignerWithKeyFile(), 参考token_test.go
3. 生成免登url: 
    - 通过用户信息Userinfo结构生成: NewLoginURL(userinfo, app)
