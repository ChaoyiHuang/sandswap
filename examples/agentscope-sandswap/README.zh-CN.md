# AgentScope 与 SandSwap 的 MCP 集成

[English](README.md) | [简体中文](README.zh-CN.md)

这是独立的 AgentScope 集成示例，自带资源初始化脚本、编程测试项目、任务提示词、
接口检查和独立验收脚本。示例所需文件均位于本目录。

## 集成方案

`Agent → Toolkit → MCPTool → MCP Python SDK → HTTPS /mcp → tinyVM`

Agent 运行在虚拟机外。SandSwap 提供 12 个 MCP 工具，命令与文件操作均在 tinyVM
内完成，模型凭证保留在 Agent 进程中。集成使用 AgentScope 公开的 `MCPTool` 适配器
和 MCP SDK 传输接口。固定版本的 `HttpMCPConfig` 没有暴露 TLS 上下文和连接池参数，
因此 `client.py` 自行管理 HTTP 客户端：校验 CA 与主机名、发送两个鉴权请求头，
通过 `keepalive_expiry=None` 复用连接。客户端的生命周期状态与 SandSwap 服务端的
无会话协议分别管理。

Agent 的系统提示词包含 `sandswap_guide`。MCP 的 `isError` 转换为 AgentScope
工具错误；命令的非零 `exit_code` 需要单独检查。网络异常后的副作用可能无法确定，
因此不自动重放修改操作。退出时关闭模型客户端、MCP 连接和 HTTP 连接池。

## 运行完整示例

以下命令均在仓库根目录执行。前提条件：Python 3.11+、健康的独立 SandSwap 部署、
具有管理权限的 `output/sandctl`，以及已注册且包含 Python 和 Git 的 `ubuntu:24.04`
模板。部署方式见[裸机部署脚本](../../deploy/baremetal/deploy-single-node.sh)。
依赖固定到使用 AgentScope 2.x `Agent` / `MCPTool` API 的已验证版本。

### 1. 安装依赖

```sh
python3 -m venv /tmp/agentscope-sandswap-venv
PY=/tmp/agentscope-sandswap-venv/bin/python
EXAMPLE=examples/agentscope-sandswap
"$PY" -m pip install -r "$EXAMPLE/requirements.txt"
```

### 2. 创建全新的测试资源

```sh
ROUND_DIR=output/agentscope-round-1
"$PY" "$EXAMPLE/setup.py" --output-dir "$ROUND_DIR/setup"
source "$ROUND_DIR/setup/env.sh"
```

`setup.py` 创建两个新 Agent 和三个新的 flat SandFS，每个沙箱配置为 2 vCPU /
512 MiB：两个归主测试 Agent 所有，一个归隔离测试 Agent 所有。脚本将 `fixtures/`
中的项目写入主沙箱的空工作区，创建初始 Git 提交，再将新沙箱 ID 填入 [TASK.md](TASK.md)。
脚本拒绝向非空工作区写入，不会按名称选用已有沙箱。

输出目录权限为 0700；`env.sh` 保存主 Agent 的 key，权限为 0600。另一个 Agent 的
key 不会传给 MCP 客户端。`resources.json` 随资源创建进度记录 ID，失败时也保留已创建
资源的信息。每轮使用新的 `ROUND_DIR`。可选参数包括 `--sandctl`、`--template`、
`--mcp-url`、`--ca`，详见 `setup.py --help`。

### 3. 检查 MCP 行为与初始失败状态

```sh
"$PY" "$EXAMPLE/check.py" --output-dir "$ROUND_DIR/contract" --samples 100
"$PY" "$EXAMPLE/verify.py" --output "$ROUND_DIR/before.json"
```

`check.py` 覆盖全部 12 个工具、TLS/鉴权、隔离、文本与二进制文件、后台任务完成/
终止/租约到期、重连持久性，以及两组各 100 次的串行命令延迟采样。脚本只写入名称
唯一的 `agentscope-check-*` 目录，成功后删除；失败时应检查该目录，或另起一轮全新
测试，再进行编程任务验收。

`verify.py` 确认本示例的独立测试项目初始有 5 个测试，其中 3 个失败。编程任务是在
保持测试不变的前提下，修复加法和 Fibonacci 函数。

### 4. 调用真实模型并独立验收

```sh
export MODEL_API_KEY='<model key>'
export MODEL_BASE_URL=https://open.bigmodel.cn/api/paas/v4
export MODEL_NAME=glm-5.3-flash
"$PY" "$EXAMPLE/run.py" --task "$ROUND_DIR/setup/task.md" --output-dir "$ROUND_DIR/agent"
"$PY" "$EXAMPLE/verify.py" --baseline "$ROUND_DIR/before.json" --output "$ROUND_DIR/after.json"
```

生成的任务要求完成 MCP 工具发现、文件读取、运行失败测试、修复代码、通过测试和
创建 `fix calc` 提交。`run.py` 要求 Agent 正常完成，且所有工具调用成功、仅使用
SandSwap 工具。`verify.py` 再独立检查：5 个测试全通过、测试文件 SHA-256 未改变、
额外函数边界检查通过、恰好新增一个 `fix calc` 提交、工作区干净。模型最终回复不能
替代这些验收结果。

### 5. 保留私有证据并清理

原始模型/工具事件和结果保存在 `ROUND_DIR` 中；默认位于 Git 忽略的 `output/` 下。
对外只提交脱敏汇总。按 `resources.json` 记录，先使用
`output/sandctl api sandfs delete <sandfs-id>` 删除本轮 SandFS，再使用
`output/sandctl api agent delete <agent-id>` 删除本轮 Agent。使用完毕后删除 `env.sh`，
并取消 `MODEL_API_KEY` 和 `SANDSWAP_API_KEY` 环境变量。如果为独占测试部署临时停止
了主机服务，测试结束后应恢复。

## 适用范围与兼容性

- Python 3.13 要求 CA 具有合适的密钥用途扩展。旧测试 CA 需使用更新后的裸机证书
  生成脚本重新签发；仅修改脚本不会更新已部署证书。TLS 校验始终启用。
- 缺失或无效 key 应返回 HTTP 401。本次修复了错误响应无法关联 JSON-RPC 请求 ID、
  导致 MCP SDK 等待的问题。
- 两组延迟采样均使用预热后的连接，不代表虚拟机冷启动时间。
- MCP SDK 2.3.0 即使配置 `follow_redirects=True` 也拒绝跨源重定向。本示例验证单个
  网关，不覆盖多网关路由、节点故障切换或集群负载，也不涉及 K8s 集成。

独立流程的实测结果见[测试结果与问题分析](RESULTS.zh-CN.md)。

## 参考资料

- [AgentScope MCP 文档](https://docs.agentscope.io/latest/en/building-blocks/tool/overview)
- [已审阅的 MCP 客户端源码](https://github.com/agentscope-ai/agentscope/blob/b76f2726751e774541ece42256def65c247d4131/src/agentscope/mcp/_mcp_client.py)
- [已审阅的 MCPTool 适配器源码](https://github.com/agentscope-ai/agentscope/blob/b76f2726751e774541ece42256def65c247d4131/src/agentscope/tool/_adapters.py)
- [SandSwap MCP 接口约定](../../docs/integration/agent-mcp.md)
