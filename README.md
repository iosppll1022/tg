# TelegramAntiRecall — 防撤回 dylib 源码

面向 **ph.telegra.Telegraph 13.0 (35303)** 的可注入动态库。  
把 Postbox 落库删除入口短路，使「对方撤回」后**本地已缓存**的消息原文仍保留。

> 分析1 / 分析2 默认交付仍是**二进制补丁**；本仓库仅在明确要求「弄 dylib / 发源码」时使用。

---

## 原理

Telegram 撤回不是纯 UI 隐藏，而是服务端推送：

`updateDeleteMessages` / `updateDeleteChannelMessages`
→ AccountState 累积删除操作
→ **Postbox.Transaction** 从本地库删消息

本 dylib hook / 短路两处导出方法（与静态补丁同一入口）：

| 符号（Swift mangled） | 样本偏移* | 作用 |
|---|---|---|
| `_$s7Postbox11TransactionC14deleteMessages_12forEachMediaySayAA9MessageIdVG_yAA0G0_pcSgtF` | `0x163940` | 按 MessageId 删除（含频道、Core `_internal_deleteMessages`） |
| `_$s7Postbox11TransactionC27deleteMessagesWithGlobalIds_12forEachMediaySays5Int32VG_yAA0J0_pcSgtF` | `0x164a0c` | 全局 ID 删除（普通私聊/群 `updateDeleteMessages`） |

\*偏移仅作 **13.0/35303** fallback；正常路径用 `dlsym` 按符号解析，**换版务必重核**。

**未 hook** `deleteMessagesInRange`（降低误伤按范围清理）。

安装优先级（编译期能链到什么就用什么）：

1. `MSHookFunction`（ElleKit / Cydia Substrate / Substitute）
2. `LHHookFunctions`（libhooker）
3. **fishhook** `rebind_symbols`（重绑调用方 GOT）
4. 对导出函数入口写 ARM64 `RET`（`0xD65F03C0`，与字节补丁等价）

---

## 边界（与二进制补丁相同）

1. 只对**本机已下载/缓存**的消息有效；从未打开过的会话救不回正文。  
2. 自己点删除（仅对我/对所有人）时，本地也可能删不掉（共用 `deleteMessages`）。  
3. 未做「对方试图撤回」角标/横幅。  
4. 其它官方客户端仍会按官方逻辑消失。  
5. 秘密聊天、阅后即焚等不在保证范围。  
6. **符号被 strip / 换版改名**时依赖偏移 fallback，极易失效——请用 `rabin2 -E PostboxFramework | grep deleteMessages` 核对。

---

## 目录

```
TelegramAntiRecall/
  README.md
  Makefile              # Theos tweak
  Makefile.clang        # 仅 clang + iOS SDK 出 dylib
  control               # Theos 包装
  TelegramAntiRecall.plist   # 进程过滤
  src/AntiRecall.m      # 主逻辑
  vendor/fishhook/      # Facebook fishhook（BSD）
```

---

## 编译

### A. Theos（越狱 tweak → .deb）

```bash
export THEOS=/path/to/theos   # 或 theos-roothide
cd TelegramAntiRecall
make package
```

生成的 dylib 一般在 `.theos/obj/`；安装后由 Substrate/ElleKit 按 plist 注入 `Telegram`。

若环境已有 `substrate.h`，可在 `Makefile` 里取消 `TelegramAntiRecall_LIBRARIES = substrate` 注释，这样会走 `MSHookFunction` 路径（推荐）。

### B. clang + iPhoneOS SDK（只要 .dylib）

**macOS / Xcode：**

```bash
make -f Makefile.clang \
  SDK="$(xcrun --sdk iphoneos --show-sdk-path)" \
  CC="$(xcrun --sdk iphoneos -f clang)"
# => build/TelegramAntiRecall.dylib
```

**Linux + Theos 工具链示例：**

```bash
make -f Makefile.clang \
  SDK=$THEOS/sdks/iPhoneOS16.5.sdk \
  CC=$THEOS/toolchain/linux/iphone/bin/clang
```

可选：`ldid -S build/TelegramAntiRecall.dylib`（按你的签名流程）。

---

## 注入方式

### 1) 越狱：ElleKit / Substitute / Substrate

- 编 Theos 包安装，或把 `TelegramAntiRecall.dylib` + `TelegramAntiRecall.plist` 丢到  
  `/Library/MobileSubstrate/DynamicLibraries/`（或 ElleKit 对应目录）。  
- plist 已过滤 `ph.telegra.Telegraph` / 可执行名 `Telegram`。  
- 杀进程重开 Telegram，看 Console / `oslog` 是否有 `[TelegramAntiRecall] init`。

### 2) 侧载：insert_dylib 写进主程序 / 任意常驻 framework

```bash
# 示例：把 dylib 拷进 App，并给主 binary 加 LC_LOAD_DYLIB
insert_dylib --all-yes --inplace \
  '@rpath/TelegramAntiRecall.dylib' \
  Payload/Telegram.app/Telegram

mkdir -p Payload/Telegram.app/Frameworks
cp TelegramAntiRecall.dylib Payload/Telegram.app/Frameworks/
# 视情况装入 Frameworks 并保证 @rpath 能搜到
```

然后用你的 Apple ID / 企业证**整包重签**（含新 dylib）。

也可用 `optool` / `install_name_tool` / 手工加 load command，原理相同：进程启动时 dyld 加载本库，`constructor` 自动安装 hook。

### 3) 调试器临时注入（仅测试）

```text
lldb: process load /path/TelegramAntiRecall.dylib
```

---

## 换版核对（重要）

```bash
rabin2 -E PostboxFramework.framework/PostboxFramework | grep deleteMessages
# 或
nm -gU PostboxFramework | grep deleteMessages
```

确认两行 mangled 名仍在且地址更新后：

1. 优先只靠符号——一般不用改源码；  
2. 若符号没了，改 `AntiRecall.m` 里 `AR_OFF_*` 并重新测试；  
3. 切勿把 13.0 的偏移用在其它版本上还当成功。

---

## 日志

设备上过滤：

```text
TelegramAntiRecall
```

成功时大致会看到 `dlsym deleteMessages=...` 以及 `MSHookFunction installed` 或 `RET patch => del=1 gid=1`。

---

## 许可

- 本仓库自研部分：按需自用。  
- `vendor/fishhook`：Facebook BSD 许可，见源文件头。
