# 索引 AUI 数据形式与生成过程概览

本文针对 ST-VLS 项目的认证索引（Authenticated Index, AUI），按照构建流程逐步展示各阶段的核心数据结构，并辅以从示例数据（取自 `us-colleges-and-universities.csv` 的首条记录）中截取的真实片段，便于汇报道具。

## 1. 数据拥有者输入
- **原始字段**：`id`, `x`, `y`, `keywords`（经 `prepare_dataset.load_and_transform` 归一化）
- **配置参数**：来自 `conFig.ini`，包含
  - 空间 GBF：`size=m1`, `hash_count=k_spa`, `psi`（每单元比特数）
  - 关键词 GBF：`size=m2`, `hash_count=k_tex`, `psi`
  - 其他：`lambda`（安全参数）、`s`（受限密钥前缀长度）、`U`（CSP 数量）、Cuckoo 哈希参数等

## 2. `SpatioTextualRecord` 对象
`convert_dataset` 将每条字典记录映射为：

```python
SpatioTextualRecord(
    id=133872,
    x=28.0667,
    y=-81.9500,
    keywords="Florida Southern College Lakeland",
    spatial_gbf=<GarbledBloomFilter size=100 psi=32>,
    keyword_gbf=<GarbledBloomFilter size=200 psi=32>
)
```

- `spatial_gbf` 写入原始坐标 token `"28.0667,-81.95"` 及网格 token `CELL:R56_C-164`。
- `keyword_gbf` 写入归一化分词：`["florida", "southern", "college", "lakeland"]`。

## 3. 原始 GBF 数据形态
每个 GBF 是长度固定的字节数组列表（值通过 XOR 累加份额得到）。示例的首条记录片段：

```
spatial_gbf.array[0] = 0x46a740bc
keyword_gbf.array[0] = 0xb14eafc7
```

- 共有 `m1=100` 个空间槽位、`m2=200` 个文本槽位。
- `psi=32` 比特 ⇒ 每个槽位是 4 字节。

## 4. 一次性掩码加密（`F` 函数）
`Setup` 使用随机密钥 `Ke` 对每条记录生成长度 `(m1+m2)×segment_length` 的掩码：

```
Ke = 0x34da4199222c2cc179fc0e0bb7ddde1e
pad_i = F(Ke, str(row_index) || str(object_id), total_len)
```

- 空间部分：`Ebp[i][j] = spatial_gbf.array[j] XOR pad_i[j]`
- 关键词部分：`EbW[i][j] = keyword_gbf.array[j] XOR pad_i[m1+j]`

示例截取：

```
Ebp[0][0] = 0x46a740bc
EbW[0][0] = 0xb14eafc7
```

（单条记录时 XOR 后与原值相同；多记录情况下为密文混合值。）

## 5. 认证标签 σ 生成（FX + HMAC）
对所有记录的原始 GBF 列执行 FX PRF 累加并与 HMAC 标签异或，得到固定长度证明份额。

```
Kv = 0x49f54b18bc1d93840684e0e1effe301c  # 由受限密钥生成
Kh = 0x3caaa84f44a438b9aa33082b786e2bd5
sigma_spa[j] = XOR_i FX(K_i, raw_spa_i[j]) XOR HMAC(Kh, j || ids_concat)
sigma_tex[j] = 类似操作
```

示例首列：

```
sigma_spa[0] = 0x4af9e66d8c3d3a24de8ebfca96348060
sigma_tex[0] = 0x5b2532e0502294ccc59cc08e0fc94d0f
```

## 6. 最终 AUI 字典形态

```python
aui = {
    "I_spa": {
        "Ebp": [  # n 条记录，每条含 m1 个 4 字节密文
            [b"F\xA7@\xBC", ...]  # 例：记录 1
        ],
        "sigma": [b"J\xF9\xE6m\x8C=:$\xDE\x8E\xBF\xCA\x964\x80`", ...]
    },
    "I_tex": {
        "EbW": [  # n × m2
            [b"\xB1N\xAF\xC7", ...]
        ],
        "sigma": [b"[%2\xE0P\"\x94\xCC\xC5\x9C\xC0\x8E\x0F\xC9M\x0F", ...]
    },
    "segment_length": 4,
    "security_param": 16,
    "m1": 100,
    "m2": 200,
    "k_spa": 3,
    "k_tex": 4,
    "U": 3,
    "ids": [133872, ...],
    "cuckoo_spa": {"kappa": 3, "load": 1.27, "seed": "cuckoo-seed-spa"},
    "cuckoo_kw": {"kappa": 3, "load": 1.27, "seed": "cuckoo-seed"}
}
```

- `Ebp`/`EbW` 是 CSP 缓存的密态列向量。
- `sigma` 列在查询阶段与 CSP 返回的证明份额 XOR，供客户端验证。
- 其余元数据为查询规划与 DMPF 拆分提供参数。

## 7. 产物与密钥分发
- **AUI (`aui.pkl`)**：发送给所有 CSP。
- **密钥三元组 (`K.pkl`)**：仅客户端持有 `(Ke, Kv, Kh)`，分别用于：
  1. 解密向量 (`Ke`)
  2. 生成 FX 子密钥 (`Kv → K_i`)
  3. 验证 HMAC (`Kh`)

以上流程确保云端仅见密态列及 σ 份额，查询端则可在不泄露访问模式的情况下恢复命中并验证完整性。
