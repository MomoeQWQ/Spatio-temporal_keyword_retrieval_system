import math
from core.GBF import GarbledBloomFilter
from core.QueryUtils import tokenize_normalized

class SpatioTextualRecord:
    def __init__(self, id, x, y, keywords, spatial_config: dict, keyword_config: dict, spatial_grid: dict | None = None):
        self.id = id
        self.x = x
        self.y = y
        self.keywords = keywords

        # 构造空间 GBF 对象，并添加 "x,y" 信息
        self.spatial_gbf = GarbledBloomFilter(
            size=spatial_config.get("size", 100),
            hash_count=spatial_config.get("hash_count", 3),
            psi=spatial_config.get("psi", 32)
        )
        # 原始坐标 token（占位）
        spatial_item = f"{x},{y}"
        self.spatial_gbf.add(spatial_item)
        # 网格 cell token：CELL:R{row}_C{col}
        if spatial_grid:
            lat_step = float(spatial_grid.get("cell_size_lat", 0.5))
            lon_step = float(spatial_grid.get("cell_size_lon", 0.5))
            row = math.floor(float(x) / lat_step)
            col = math.floor(float(y) / lon_step)
            self.spatial_gbf.add(f"CELL:R{row}_C{col}")

        # 构造关键词 GBF 对象，并添加关键词字符串
        self.keyword_gbf = GarbledBloomFilter(
            size=keyword_config.get("size", 200),
            hash_count=keyword_config.get("hash_count", 4),
            psi=keyword_config.get("psi", 32)
        )
        # 将关键词字符串标准化分词，逐个加入 GBF 以支持多关键词查询
        for tok in tokenize_normalized(str(keywords)):
            self.keyword_gbf.add(tok)

def convert_dataset(dict_list: list, config: dict) -> list:
    """
    将字典列表转换为 SpatioTextualRecord 对象列表。
    
    参数:
      dict_list: 每个元素为字典，必须包含 'id', 'x', 'y', 'keywords'
      config: 配置字典，格式例如：
          {
              "spatial_bloom_filter": {"size": 100, "hash_count": 3, "psi": 32},
              "keyword_bloom_filter": {"size": 200, "hash_count": 4, "psi": 32}
          }
          
    返回:
      一个 SpatioTextualRecord 对象列表，每个对象预先构造了 GBF 编码后的属性
      （spatial_gbf 与 keyword_gbf 均为 GarbledBloomFilter 对象）。
    """
    spatial_config = config.get("spatial_bloom_filter", {})
    keyword_config = config.get("keyword_bloom_filter", {})
    objects = []
    grid = config.get("spatial_grid", {})
    for record in dict_list:
        obj = SpatioTextualRecord(
            id=record["id"],
            x=record["x"],
            y=record["y"],
            keywords=record["keywords"],
            spatial_config=spatial_config,
            keyword_config=keyword_config,
            spatial_grid=grid
        )
        objects.append(obj)
    return objects
