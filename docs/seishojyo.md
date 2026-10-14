# 《聖娼女 ～性奴育成学园～》咔咔喵 Siglus R2 修复记录

本案例为逐款任务 G24，针对已核对指纹的 SiglusEngine 源版本。最终“去额外加密 R2”于 **2026-10-15 获用户 iOS 咔咔喵验收**：能够进入游戏，正文、转场和存读档正常，退出重开后读档也正常。

本案例的重建流程自工具 0.2.0 起提供 `seishojyo-r2` profile，处理匹配的 SiglusEngine 原版本；不要将 YBN/YPF 或其他标题的补丁用于本款。以下历史 R2 修复与手机反馈保持独立记录，新构建的文件验证另见文末。

## 问题与修复版本

原先启动报 `secat.no_key190`。R1 保留原资源并加入 `key.toml`，文件验证通过，但用户手机测试仍报同一错误。这个结果说明，仅在包内提供密钥未解决本次实际启动问题；不据错误后缀猜测密钥编号或场景编号，也不将其当作未知资源名修改文件。

R2 在资源中实际移除了额外的 16 字节周期 XOR 层，保留公有 256 字节 XOR、原有 LZSS 压缩和场景内容：

| 文件 | R2 处理 | 保持的结构 |
|---|---|---|
| `Scene.pck` | 按原索引处理全部 190 个压缩块，各块从周期偏移 0 开始去除 extra16 XOR；文件偏移 84 的 little-endian uint32 标志由 1 改为 0 | 原块顺序、索引、长度及其余头字段；公有 XOR 与 LZSS |
| `Gameexe.dat` | 偏移 8 之后去除同一 extra16 XOR；偏移 4 的 little-endian uint32 标志由 1 改为 0 | 前 4 字节头部、文件长度；公有 XOR 与 LZSS |

这里的偏移只适用于下述源指纹匹配的版本，不是所有 Siglus 标题的通用修改规则。对 R2 两份文件重新施加原 extra16 周期并恢复标志，可逐字节还原源文件。原游戏、旧 ZIP、旧修复 ZIP 和用户存档保持原样，R2 使用独立根目录。

公开 [Siglus 场景读取实现](https://github.com/xmoezzz/siglus_rs/blob/5f358ef1360b0439e92aed2b749e8f25d8721954/crates/siglus_assets/src/scene_pck.rs) 和 [Gameexe 读取实现](https://github.com/xmoezzz/siglus_rs/blob/5f358ef1360b0439e92aed2b749e8f25d8721954/crates/siglus_assets/src/gameexe.rs) 可用于核对额外 XOR 标志的含义；源版本严格解码的公开参考为 [hiroshil 的 Decryption.cpp](https://github.com/hiroshil/SiglusEngine/blob/82cf34e37ced71c8638f5eaf449136fa3722e76d/Decryption.cpp)。这些参考用于格式核对，不据此认定咔咔喵使用了哪一份实现。

## 已核对的版本指纹

所有 SHA256 均为本次已验证版本的识别依据。

| 文件 | 字节数 | SHA256 |
|---|---:|---|
| 源 `Scene.pck` | 13,607,939 | `60affba5f824237947fdf4cbba2521f5c969095ad1b13908926f086539d196d0` |
| R2 `Scene.pck` | 13,607,939 | `4e75f803a231db9be66e7b084dbd779946afdd2193399e7f2526138ac7e36cd2` |
| 源 `Gameexe.dat` | 13,492 | `6f980594e8beb8c3f1ee489ca62ff1c00b7f86bc9149382d0989c61248de3460` |
| R2 `Gameexe.dat` | 13,492 | `8fd6b1cff8b3309ce4c8c983c514602b1ed41443f2d513d8bc8ea638d7635513` |

最终 ZIP 名为 `24_聖娼女 ～性奴育成学园～_去额外加密_R2.zip`，根目录 `G24_Kaka_R2_20261014`，大小 **3,393,274,997 字节**，整体 SHA256 为 `dd42e419da3e9de4ce31d3fc54ade74af20fc216789032114d74fa706eb7404b`。包内含 2,301 个文件：2,298 个原运行资源，以及 `Scene.pck`、`Gameexe.dat`、`PACKAGE_VERSION_R2.txt`。ZIP 使用 UTF-8 文件名、无密码；不含 Windows 可执行入口或用户存档。

这里仅公开包指纹与处理记录，游戏包和资产不在仓库提供下载。

## 文件验证证据

- 源版本先前的独立严格解码涵盖 190 个场景，解码合计 29,567,657 字节，逐块压缩长度、消费边界和脚本布局核对通过。Gameexe 解码为 69,544 字节，严格 UTF-16 验证通过，解码 SHA256 为 `bc7d46b1c6cecd37c0d32605344bdbc26ef7e167eba1f65ec2ab9a138e9f41e8`。
- R2 制作时核对源指纹、转换后指纹和额外 XOR 反向还原结果，保留压缩结构及原内容。
- 前次正式包已通过全成员 SHA256/CRC 读回、2,298 个未改运行资源的 CRC 比较，以及 7-Zip 26.01 完整测试（退出码 0）。
- 2026-10-15 的独立局部复核重新读取 ZIP 中央目录和两份修改文件、版本标记，确认全部成员目录元数据、三份文件哈希/CRC、两个标志为 0，以及 190 个块的范围和公有层哈希均符合既有报告；源两份关键文件的新鲜哈希也匹配。该轮没有再次读取全部媒体成员或重做整个 ZIP 的完整测试。

以上阶段分开记录，不将源版本的既有严格解码写成该轮新执行的 R2 无密钥解码。脱敏机器可读摘要见 [seishojyo-r2-validation.json](../evidence/seishojyo-r2-validation.json)。

## 已确认的手机结果

2026-10-15，用户先确认 R2 可以进入游戏，随后明确确认正文、转场和存读档均正常，退出重开后读档没有问题，并确认 G24 可以了。

| 验收项 | 结果来源与结论 |
|---|---|
| 进入游戏 | 用户 iOS 咔咔喵测试确认正常 |
| 正文显示 | 用户确认正常 |
| 转场 | 用户确认正常 |
| 存档与读档 | 用户确认正常 |
| 退出重开后读档 | 用户明确确认正常 |

修复任务按用户确认收尾，保留此 R2 为已验收版本，不追加无依据的资源修改。维护者没有直接操作手机；本记录对应这份 R2 和用户已测项目，不扩大为所有剧情路线、全部设备或其他源版本均已通过。

## 后续复验

若使用者自行对匹配源版本重新构建，应在独立目录和新游戏条目中验证，保留原文件与旧存档。先确认进入游戏，再检查正文、普通转场、存档/读档以及退出重开后的读档。新构建产生新的文件级记录，不能自动继承本次手机结果；出现问题时提供源指纹、实际使用包、完整错误文本和触发阶段。

更多证据边界与公开材料范围见 [验证与复现说明](verification.md)。

## 工具 0.2.0：从匹配原目录重建

```powershell
python -m kakacat_yuris inspect --profile seishojyo-r2 --source "D:\Games\seishojyo"
python -m kakacat_yuris build --profile seishojyo-r2 --source "D:\Games\seishojyo" --output "D:\KakacatOutput\seishojyo-r2"
python -m kakacat_yuris verify --output "D:\KakacatOutput\seishojyo-r2"
```

输入必须包含匹配的原 `Scene.pck`、`Gameexe.dat` 和七个运行目录。除上述两份核心指纹外，工具还检查 2,298 份媒体的路径、大小和内容 SHA256 聚合指纹：`0e38ecac9573f07c0aca5f8c283be9b70faf407176c6b7e3bcfbca8ae5f6353f`。聚合算法是媒体行仅保留 `path/size/sha256`、按 `path` 排序，以 ASCII JSON（键排序、紧凑分隔符）编码后取 SHA256。

工具在匹配配置文件中恢复转换参数，只在本机内存使用，再用固定 R2 哈希验证唯一结果。构建不执行或读取原 EXE/DLL，也不需要既有修复包。媒体原样复制；`wav` 保留该版本的 305 份 NWA 和 12 份 Ogg，其他目录也按已核对集合检查。源根目录中的存档、补丁和备份不会复制到新包。

每个新文件独立创建并读回，两个 XOR 转换都验证反向还原。构建前、准备后及 ZIP 完整读回后均复核源核心与完整媒体集合；修改内容、增删资源或转换成已修复版本都会拒绝。输出不能存在、不能与源目录相互包含；目录链接、junction/reparse 会在遍历前拒绝。空间检查为 stage 与 ZIP 预留两份数据及余量。

`verify` 既核对本次 manifest/stage/ZIP，也重新检查本 profile 的固定 R2 核心、CRLF 版本标记和媒体指纹。同步篡改 manifest 与 ZIP 不能使错误资源通过 G24 验证。

新 ZIP 使用现有 UTF-8 / ZIP64 / DEFLATE 打包器，整体哈希不要求重现旧 STORE ZIP；全部成员的路径、大小和内容哈希必须与已验收 R2 相同。构建报告保持 `NOT_TESTED_BY_THIS_BUILD`，复验报告保持 `NOT_TESTED_BY_THIS_VERIFICATION`。原有 [手机成功反馈摘要](../evidence/seishojyo-r2-validation.json) 保持原样，新的 [工具构建验证摘要](../evidence/seishojyo-tool-validation.json) 单独保存。
