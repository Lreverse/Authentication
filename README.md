
## 认证系统
- c/s结构：socket
- 客户端GUI：wxpython
- 数据库：mysql
- 加解密：hash、AES、RSA

### 项目结构

- `client.py`：客户端程序
- `server.py`：服务器端程序
- `packet.py`：包类型定义
- `tcp.py`：tcp套接字接口
- `encrypt.py`：加解密函数
- `client_key/`：客户端的RSA密钥对
- `server_key/`：服务器端的RSA密钥对
- `log/`：日志文件
  - `client_access.log`：客户端记录每次登录成功时所使用的认证码
  - `server_access.log`：服务器记录客户端的每次请求
- `Authentication.xmind`：项目的框架图

### TCP连接说明
- tcp连接是在发送登录或注册请求才会建立的，打开客户端本身是不进行任何通信的
- 登录成功后，维持该连接，也就是`tcp长连接`。但是这里没有使用心跳机制来实现，而是通过发送`exit`的类型包来告知服务器端要结束连接了。而在此期间，服务器将一直在循环接收消息
- 注册成功后，立即结束该连接了，也就是`tcp短连接`

### 安全性
- 这里不考虑敌手篡改数据包类型
- 登录
  - 使用随机生成的认证码散列`(pwd, username)`的`md5值`，能防止敌手篡改信息，保证信息的完整性
- 注册
  - 客户端使用rsa加密`username`和`(pwd, username)`的`md5值`，保证消息的机密性
  - 注册过程的用户名不能明文传输，否则敌手就可以轻易篡改，导致不合法的用户名被注入数据库中
- 修改密码
  - 客户端使用`旧的md5值`AES加密`新的md5值`为`cipher`，同时需要使用`旧的md5值`将`cipher`散列为`hash2`（这里就是把`旧的md5值`当作盐），发送`hash2`和`cipher`给服务器。这样能保证消息的完整性和机密性

### 问题（有空再修正）

- 修改密码成功后以及注册成功后，服务器返回的响应信息都没有加密，客户端无法证实消息的真实性
  - 问题：此时敌手可以篡改包类型，使用户误以为密码修改成功或注册成功
  - 解决：对包数据进行加密（~~懒得搞了~~）
- 登录成功后的界面是直接写在客户端的，是一个继承了`mainFrame`的`Panel`。这里只是简单地根据回显去对每个`Panel`进行`Show`和`Hide`
  - 这样做当然很不好，通过情况下应该是服务器端返回页面，跟web差不多，但是考虑到要让一个tcp服务器传送一个Frame过来，似乎不太行得通。因为这里的每一个页面都是一个个类去定义的，所以按理说，客户端一定要事先拥有每个类的定义。
  - 不好的地方在于，程序容易被逆向从而获取登录后的界面，但让敌手看到了好像也没关系。（~~是的，我好像想多了...~~）

  


### 其他
- `binascii`的`hexlify`和`unhexlify`是真的好用^_^
- 写这个跟写用户需求一样，累死我了，似乎预见了我几年后为需求苦苦挣扎的模样>_<
