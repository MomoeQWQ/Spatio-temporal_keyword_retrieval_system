# QueryUtils.py

def encode_query(query):
    """
    将查询 Q 编码为 BQ = { b_R1, ..., b_RN, b_W* }。
    
    实现说明：
      - 将查询按空格拆分为多个词，每个词作为一个 b_R 块。
      - 特殊块 b_W* 定义为整个查询加上固定前缀 "WSTAR:"，
        以便后续能够区分出这个特殊块。
    
    参数:
        query (str): 用户输入的查询字符串。
    
    返回:
        list[str]: 包含 b_R1, ..., b_RN 和 b_W* 的块列表。
    """
    tokens = query.split()
    if not tokens:
        tokens = [query]
    R_blocks = tokens
    b_W_star = "WSTAR:" + query
    return R_blocks + [b_W_star]

def split_into_segments(b, segment_length):
    """
    将数据块 b 按固定长度 segment_length 分割为若干段（m' 段）。
    
    实现说明：
      - 按照指定的 segment_length 将字符串切分为多个片段，
        如果最后一段不足 segment_length，则在右侧补 "0" 直到满足长度。
    
    参数:
        b (str): 需要分割的数据块。
        segment_length (int): 每个分段的固定长度。
    
    返回:
        list[str]: 分段后的子字符串列表。
    """
    segments = []
    for i in range(0, len(b), segment_length):
        seg = b[i:i+segment_length]
        if len(seg) < segment_length:
            seg = seg + "0" * (segment_length - len(seg))
        segments.append(seg)
    return segments

def identify_bW_star(BQ):
    """
    从 BQ 中识别并返回特殊块 b_W*。
    
    实现说明：
      - 假设 b_W* 具有固定前缀 "WSTAR:"，
        遍历 BQ 中的块，返回首个以该前缀开头的块。
      - 如果未找到符合条件的块，则默认返回列表中的最后一个元素。
    
    参数:
        BQ (list[str]): 查询编码得到的块集合。
    
    返回:
        str: 特殊块 b_W*。
    """
    for b in BQ:
        if b.startswith("WSTAR:"):
            return b
    return BQ[-1]

def pad_query_blocks(BQ, max_r_blocks: int, dummy_token_prefix: str = "DUMMY:"):
    """
    Pad the R blocks in BQ to a fixed length to suppress leakage.
    Leaves the special b_W* untouched (assumed at the end).
    """
    if not BQ:
        return BQ
    bW = identify_bW_star(BQ)
    R = [b for b in BQ if b != bW]
    if len(R) >= max_r_blocks:
        R = R[:max_r_blocks]
    else:
        need = max_r_blocks - len(R)
        R += [f"{dummy_token_prefix}{i}" for i in range(need)]
    return R + [bW]

# ---------------------
# Normalization Helpers
import re

def normalize_token(tok: str) -> str:
    """Uppercase alphanumeric only (remove other chars)."""
    t = tok.upper()
    t = re.sub(r"[^A-Z0-9]", "", t)
    return t

def tokenize_normalized(text: str) -> list:
    """Split on whitespace, normalize each token, drop empties."""
    raw = re.split(r"\s+", str(text))
    out = []
    for r in raw:
        n = normalize_token(r)
        if n:
            out.append(n)
    return out
