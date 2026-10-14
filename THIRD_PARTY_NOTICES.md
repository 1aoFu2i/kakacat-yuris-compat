# 第三方来源与许可

本项目用途为咔咔喵（KrkrCat）中的已知 YU-RIS 游戏兼容适配。游戏引擎、原作、汉化资产、源游戏与生成的游戏包不属于本项目授权内容。

## MoleBox

`kakacat_yuris/molebox.py` 的 NewDES 数据与封装读取规则来自 Alexey Sudachen 的 [MoleBox 源码](https://github.com/sudachen/Molebox/tree/f526e8a41bcb7884231154e8e5ccb74c789f188d)，固定提交 `f526e8a41bcb7884231154e8e5ccb74c789f188d`，遵循 GPL-3.0。公开改造将必要 rotor 内联，取消本机 vendor 文件存在性依赖，保留版本指纹、资源范围和校验规则。

Blowfish 由 `cryptography` 完成，CRC32 使用 Python zlib，CRC16 使用多项式 `0xA001`、初始零的短小实现。项目不编译、调用或附带 xternal C 源码。

## Enigma Virtual Box 读取

`kakacat_yuris/evb.py` 以 [mos9527/evbunpack 0.2.6](https://github.com/mos9527/evbunpack/tree/ee7b647acf2a46617b0c448dfa83d63132ea917b) 的文件树结构/读取代码为依据，固定提交 `ee7b647acf2a46617b0c448dfa83d63132ea917b`，保留 Apache-2.0 许可。适配范围限定为已验证的未压缩 EVB 资源，不包含 PE 重构/执行路径，不使用 pefile 或 aplib 解压。

## cryptography

运行依赖锁定为 `cryptography==50.0.2`，该库遵循其 Apache-2.0 或 BSD 许可；依赖安装包包含自己的许可及所捆绑组件说明。相关信息见 [cryptography 官方仓库](https://github.com/pyca/cryptography)。本项目只调用 Cipher/Blowfish 接口。

## 格式资料

[YU-RIS 官方 CG 手册](https://yu-ris.net/manual/yu-ris/html/cg/cg.html) 用于 T、TA 等参数语义参考。[GARbro](https://github.com/morkt/GARbro) 的 YPF 格式研究亦为历史格式核对资料。公开 YPF 读取器独立实现名称长度 CRC 匹配及边界验证，没有复制来源不明的名称交换表。历史 yuri/YuRISTools 资料不作为复制进本项目的源码依赖。

各文件保留自身来源和修改说明；项目新增代码与文档遵循根目录的 GPL-3.0-only。运行工具不需要访问上述站点，也不会外发游戏或报告。
