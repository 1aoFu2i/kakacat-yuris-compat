# 咔咔喵兼容适配：YU-RIS / Siglus 游戏修复流程与工具

本项目整理 **咔咔喵（KrkrCat）中的 YU-RIS 与已支持的 Siglus 游戏兼容适配**。提供中文案例和本地工具，覆盖已知版本的汉化资源加载、启动格式兼容、读档画面恢复及转场处理。使用者自行提供匹配的源游戏；工具只读取源目录，在新的输出目录生成可导入资源包。

现有 `kakacat_yuris` 工具支持《乐园之扉HD》（euphoria HD）的原版与高清步兵变体，以及《妖蛆之饵》（Maggot Baits）。支持范围由关键文件 SHA256 确定，不按相似游戏名自动套用修改。

工具自 **0.2.0** 起另支持 [《聖娼女 ～性奴育成学园～》SiglusEngine R2](docs/seishojyo.md)，profile 为 `seishojyo-r2`。它从匹配的原目录重建去额外 XOR 层的资源包，严格绑定两份核心文件及完整媒体集合指纹。历史 R2 已获用户手机验收；新构建的手机状态单独记录。

## 已确认结果

| 游戏 / 兼容处理 | 文件验证 | 咔咔喵 iOS 结果 |
|---|---|---|
| 乐园原版 R1：读档持续黑块 | 已通过 | 用户确认已测场景解决；完整测试清单未逐项确认 |
| 乐园原版 R2：全画面转场，包含 R1 | 已通过 | 待转场与读档回归验收 |
| 乐园高清步兵变体 R1＋R2 | 已通过 | 待本版本汉化、转场与读档验收 |
| 妖蛆 R1：读档黑屏 / 立绘恢复 | 已通过 | 用户确认 1、2、6、7 号存档直接读档和退出重开后读档均正常 |
| 聖娼女（G24）Siglus R2：去除额外 XOR 层 | 已通过 | 2026-10-15 用户确认进入游戏、正文、转场、存读档及退出重开后读档均正常 |

手机结果来自用户反馈，维护者没有直接操作 iOS 设备。重新构建或校验只产生文件级证据，不会自动把待验收项目改成手机成功，也不证明唯一的解释器或 GPU 根因。

## 安装

使用 Python **3.12**，建议在独立虚拟环境安装。Windows PowerShell 示例：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\python.exe -m kakacat_yuris --help
```

MoleBox 提取使用锁定的 `cryptography==50.0.2`。EVB 读取及 YPF/YBN 校验使用本项目自包含代码，不需要恢复或运行 Windows EXE，不依赖旧修复工作区。

## 快速使用

先自行解压源游戏。YU-RIS profiles 的 `--source` 指向包含 `pac/` 和汉化 EXE 的游戏根目录；G24 的输入要求见下方示例。游戏目录、原存档和旧适配包均保留；输出目录必须尚不存在，且与源目录树分离。

```powershell
python -m kakacat_yuris inspect --profile euphoria-r1 --source "D:\Games\euphoriaHD"
python -m kakacat_yuris build --profile euphoria-r1 --source "D:\Games\euphoriaHD" --output "D:\KakacatOutput\euphoria-r1"
python -m kakacat_yuris verify --output "D:\KakacatOutput\euphoria-r1"
```

| Profile | 输入版本 | 生成的咔咔喵兼容处理 |
|---|---|---|
| `euphoria-r1` | 已支持的乐园原版 | 汉化资源准备＋已获用户成功反馈的读档终点处理 |
| `euphoria-r2` | 同一乐园原版 | 汉化资源准备＋R1＋全画面转场候选 |
| `euphoria-alt-r2` | 已支持的高清步兵变体 | 保留本版资源组合＋汉化资源准备＋R1＋R2 |
| `maggot-r1` | 已支持的妖蛆原始汉化版本 | EVB 读取＋五 YPF 合并＋V3/V4 兼容处理＋R1 |
| `seishojyo-r2` | 已核对的聖娼女 G24 Siglus 原版本 | 按 190 个场景块去额外 XOR、配置同步处理、保留公有 XOR 与 LZSS |

输出包含 `stage/` 游戏目录、以 profile 命名的无 EXE ZIP、`manifest.json` 和 `validation.json`。包中的原 DLL 属于保留资源，构建过程中不会执行。将 ZIP 独立导入咔咔喵，保留旧游戏条目；手机验收步骤见对应案例。

`inspect` 是只读检查；`build` 遇到版本不匹配、损坏数据或已有输出会拒绝继续。失败时保留本次输出目录及简要错误记录，修正原因后改用新的输出目录。

### G24 R2 从原目录构建

输入根目录需要原始 `Scene.pck`、`Gameexe.dat`，以及 `bgm/dat/g00/gan/koe/mov/wav` 七个运行目录。工具检查核心文件和媒体聚合指纹，在本机恢复所需转换参数；不需要旧修复包、单独密钥文件或 Windows 游戏运行环境。

```powershell
python -m kakacat_yuris inspect --profile seishojyo-r2 --source "D:\Games\seishojyo"
python -m kakacat_yuris build --profile seishojyo-r2 --source "D:\Games\seishojyo" --output "D:\KakacatOutput\seishojyo-r2"
python -m kakacat_yuris verify --output "D:\KakacatOutput\seishojyo-r2"
```

输出为 `seishojyo-r2.zip`、独立 `stage/G24_Kaka_R2_20261014/`、`manifest.json` 与 `validation.json`。仅加入七个运行目录和三份根文件；源 EXE、DLL、补丁、备份及 `savedata` 均保留在原目录。完整输出需要约 6.8GB 加余量；工具在复制前核对可用空间。源或运行资源中的链接/reparse，以及已存在输出（含悬空链接）会被拒绝。

新包的 ZIP 压缩流和整体哈希可以与旧 R2 不同。复现目标是全部 2,301 个成员的路径、大小与内容 SHA256 相同；[工具验证摘要](evidence/seishojyo-tool-validation.json) 与 [既有手机验收摘要](evidence/seishojyo-r2-validation.json) 分开保留。

## 案例与验证

- [乐园之扉HD：汉化加载、R1 和 R2](docs/euphoria.md)
- [妖蛆之饵：完整适配链与四档验收](docs/maggot-baits.md)
- [聖娼女（G24）：Siglus R2 去额外加密与手机验收](docs/seishojyo.md)
- [文件验证、压缩版本与手机验收边界](docs/verification.md)
- [本次公开工具的本地复验摘要](evidence/local-validation.json)
- [第三方来源与许可](THIRD_PARTY_NOTICES.md)

历史 BN 哈希在 zlib 1.3.1 环境可作逐字节复现约束；其他 zlib 版本按展开后的脚本、资源内容和允许改动范围验收，并记录新哈希。ZIP 时间戳和压缩流可能变化，使用本次清单核对成员内容，不要求新 ZIP 重现旧 ZIP 整体哈希。

## 贡献与许可

运行合成测试：`python -m unittest discover -s tests -v`。仓库测试不含真实游戏脚本、图片或存档。反馈问题时提供 profile、工具版本、Python/zlib 版本、失败阶段和脱敏错误；请勿提交游戏资产、个人存档或凭据。

项目代码和文档按 [GPL-3.0-only](LICENSE) 发布，保留各第三方组件的原许可和署名。许可不涵盖使用者自行提供的游戏、汉化资源及生成的游戏包。仓库不提供这些资产的下载。
