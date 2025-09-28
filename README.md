# ECDH 加密通信系统

一个基于椭圆曲线 Diffie-Hellman (ECDH) 密钥交换的端到端加密通信系统，包含 Go 后端服务和 Vue.js 前端应用。

## 🚀 项目概述

本项目实现了一个安全的加密通信系统，使用 ECDH 密钥交换协议在客户端和服务器之间建立共享密钥，然后使用 AES-256-CBC 加密进行安全通信。

### 核心特性

- 🔐 **ECDH 密钥交换**: 使用椭圆曲线密码学安全地交换密钥
- 🛡️ **AES-256-CBC 加密**: 使用行业标准的对称加密算法
- 🌐 **前后端分离**: Go 后端 API + Vue.js 前端界面
- 🔄 **实时通信**: 支持加密消息的实时发送和接收
- ✅ **CryptoJS 兼容**: 前后端加密算法完全兼容

## 📁 项目结构

```
ecdh-vg/
├── be/                     # Go 后端服务
│   ├── main.go            # 主服务文件
│   ├── go.mod             # Go 模块依赖
│   └── go.sum             # 依赖校验文件
├── fe/                     # Vue.js 前端应用
│   ├── src/
│   │   ├── components/    # Vue 组件
│   │   ├── utils/         # 工具函数
│   │   ├── assets/        # 静态资源
│   │   ├── App.vue        # 根组件
│   │   └── main.js        # 入口文件
│   ├── public/            # 公共资源
│   ├── package.json       # 前端依赖配置
│   └── vue.config.js      # Vue 配置文件
└── README.md              # 项目说明文档
```

## 🛠️ 技术栈

### 后端 (Go)
- **Go 1.24.4**: 主要编程语言
- **Gorilla Mux**: HTTP 路由器
- **goArsenal**: 加密工具库
- **ECDSA**: 椭圆曲线数字签名算法
- **AES**: 高级加密标准

### 前端 (Vue.js)
- **Vue 3.2.13**: 渐进式 JavaScript 框架
- **Axios**: HTTP 客户端
- **CryptoJS**: JavaScript 加密库
- **ethereum-cryptography**: 以太坊加密工具
- **Vue CLI**: 项目构建工具

## 🚀 快速开始

### 环境要求

- Go 1.24.4 或更高版本
- Node.js 16+ 和 npm/yarn
- 现代浏览器支持

### 后端启动

```bash
# 进入后端目录
cd be

# 安装依赖
go mod tidy

# 启动服务器
go run main.go
```

后端服务将在 `http://localhost:8081` 启动

### 前端启动

```bash
# 进入前端目录
cd fe

# 安装依赖
npm install
# 或使用 yarn
yarn install

# 启动开发服务器
npm run serve
# 或使用 yarn
yarn serve
```

前端应用将在 `http://localhost:8080` 启动

## 📡 API 接口

### POST /public-key
交换公钥接口

**请求体:**
```json
{
  "publicKey": "客户端公钥的十六进制字符串"
}
```

**响应:**
```json
{
  "publicKey": "服务器公钥的十六进制字符串"
}
```

### POST /encrypted-message
发送加密消息接口

**请求体:** Base64 编码的加密消息

**响应:** Base64 编码的加密响应消息

## 🔐 加密流程

1. **密钥生成**: 客户端和服务器各自生成 ECDH 密钥对
2. **公钥交换**: 通过 `/public-key` 接口交换公钥
3. **共享密钥计算**: 双方使用对方公钥和自己私钥计算共享密钥
4. **消息加密**: 使用 AES-256-CBC 和共享密钥加密消息
5. **安全通信**: 通过 `/encrypted-message` 接口发送加密消息

## 🔧 开发说明

### 前端开发

```bash
# 代码检查
npm run lint

# 构建生产版本
npm run build
```

### 后端开发

```bash
# 运行测试
go test ./...

# 构建可执行文件
go build -o ecdh-server main.go
```

## 🛡️ 安全特性

- **前向安全性**: 每次会话使用新的密钥对
- **端到端加密**: 消息在传输过程中始终保持加密状态
- **密钥隔离**: 私钥永不离开本地环境
- **算法安全**: 使用经过验证的加密算法和实现

## 📝 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进这个项目！

## 📞 联系方式

如有问题或建议，请通过以下方式联系：

- 创建 [Issue](../../issues)
- 提交 [Pull Request](../../pulls)

---

⭐ 如果这个项目对你有帮助，请给它一个星标！
