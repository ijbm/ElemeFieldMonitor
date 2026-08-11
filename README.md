# ElemeFieldMonitor

饿了么 (淘宝闪购) iOS 字段监控悬浮窗 Tweak

## 功能

在饿了么 App 中注入悬浮窗，实时监控并显示以下字段：
- `encryptSceneCode` — 加密场景码
- `encryptActCode` — 加密活动码
- `rightId` — 权益 ID
- `sourceFrom` — 来源标识
- `sceneCode` — 场景码
- `actCode` — 活动码

## 编译

### GitHub Actions 自动编译

1. Fork 或推送到 GitHub 仓库
2. 进入仓库 **Actions** 页面
3. 点击 **Build ElemeFieldMonitor Tweak** workflow
4. 点击 **Run workflow** 手动触发，或 push 代码自动触发
5. 编译完成后在 **Artifacts** 下载 `.deb` 或 `.dylib`

### 本地编译 (需要 Theos)

```bash
# 安装 Theos
git clone --recursive https://github.com/theos/theos.git /opt/theos
export THEOS=/opt/theos

# 编译
cd ElemeFieldMonitor
make package
```

## 安装

### 越狱设备 (Dopamine/Palera1n - Rootless)

```bash
# 通过 SSH 安装
make install THEOS_PACKAGE_SCHEME=rootless

# 或手动安装
scp packages/*.deb root@device:/var/root/
ssh root@device "dpkg -i /var/root/*.deb && killall -9 SpringBoard"
```

### 越狱设备 (unc0ver/checkra1n - Rootful)

```bash
# 修改 Makefile 中 THEOS_PACKAGE_SCHEME = rootful
make install
```

### 非越狱 (Sideloadly 注入)

1. 从 GitHub Actions Artifacts 下载 `ElemeFieldMonitor-dylib`
2. 使用 [Sideloadly](https://sideloadly.io/) 将 dylib 注入饿了么 IPA
3. 重新签名安装

## 使用

- 启动饿了么 App，2.5 秒后悬浮窗自动出现
- **拖拽标题栏**移动悬浮窗
- **双击标题栏**显示/隐藏
- **长按字段**复制单个值
- **Copy All JSON** 复制所有字段为 JSON
- **Clear** 清空所有数据

## 目标

- Bundle ID: `me.ele.ios.eleme`
- 最低系统: iOS 15.0
- 架构: arm64
