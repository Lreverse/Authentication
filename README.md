
### 认证系统
- c/s结构：socket
- 客户端GUI：wxpython
- 数据库：mysql
- 加解密：hash、AES

#### 问题（后续再进行修正）

- 修改密码成功后，服务器返回的响应信息没有加密，客户端无法证实消息的真实性
- 没有核时客户端发送的数据
  - 需要对不合理的数据进行弹窗响应(wx.MessageBox)
- 服务器端需要生成日志文件，记录每条连接、每个请求
- 注册模块还没实现