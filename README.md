# oneid-jwt-auth-go
oneid jwt auth golang sdk

## 使用步骤

1. go.mod里引用sdk: github.com/idaaser/oneid-jwt-auth v1.0.4
2. 初始化配置: NewSigner()或 NewSignerWithKeyFile(), 参考token_test.go
3. 生成免登url: NewLoginURL(userinfo, app, params...), 参数解释如下:
   - userinfo: 免登用户的信息, 见[token.go中Userinfo的定义](./token.go)
   - app: 免登应用的唯一标识, 当前支持meeting(腾讯会议), doc(腾讯文档), 详见[app.go](./app.go)
   - params: 表示自定义的key/value键值对(以query param的方式追加到免登链接之后)
4. 免登url示例:
   - userinfo为: Userinfo{ ID: "f99530d4-8317-4900-bd02-0127bb8c44de", Name: "张三", Username: "zhangsan", Email: "zhangsan@example.com", Mobile: "+86 13411112222"}
   - app为: meeting
   - params为: target_link_uri=https://www.example.com
   - 生成的免登链接为: https://oauth2.ci-731.account.tencentcs.com/v1/sso/jwtp/1102878596482998272/1151383032381308928/kit/meeting?id_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsic3NvX2FwaSJdLCJlbWFpbCI6InpoYW5nc2FuQGV4YW1wbGUuY29tIiwiZXhwIjoxNzMzMTMyMDI3LCJpYXQiOjE3MzMxMzE3MjcsImlzcyI6Imh0dHBzOi8vd3d3LmV4YW1wbGUuY29tIiwianRpIjoiYzQ3Y2JmZDA2MDcyNDVkMzllMzdkNTZiMzgwNTUxZjUiLCJuYW1lIjoi5byg5LiJIiwicGhvbmVfbnVtYmVyIjoiKzg2IDEzNDExMTEyMjIyIiwicGljdHVyZSI6Imh0dHBzOi8vd3d3LmV4YW1wbGUuY29tL2F2YXRhcjEucG5nIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiemhhbmdzYW4iLCJzdWIiOiJmOTk1MzBkNC04MzE3LTQ5MDAtYmQwMi0wMTI3YmI4YzQ0ZGUifQ.SE_yFmaJhDb_PNrirlSseM3VRQdzQtfPeQ1vAIBc4E0OUYk0vixnjRmaemEHVXwrX4nqDZjZ3oSNxIsiRi2a_ow34x_83DcWkFqczL2AGULeV7w1Pz6HRRVHABA2ZbpJQOmWAdMASRuR5Nq0oGwBhB-VTxZbPMKaVsQ_utr0Fo07kRem8RSxvpN1kG-ABnaULLgyzOcDkLnjRePhjpdg2h3A9J39Of5L09PQJW1qNkQDeZNNenEXFefRRPQy7MobxWILWeWzzxVeBNzzOBI0RPgz8TJ0Ljy5FzI1AxG6NFWlAz-CG5JwDxSytO2YzwD6rVWldVkwvbCh6qtAylItSQ&target_link_uri=https%3A%2F%2Fwww.example.com
