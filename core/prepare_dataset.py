import pandas as pd

def load_and_transform(csv_file):
    """
    读取美国大学信息数据集 CSV 文件，挑选指定列形成三元组形式：
      (id, spatial_info, keywords)
    其中:
      - id: 使用 CSV 中的 IPEDSID 字段
      - spatial_info: 从 'Geo Point' 字段提取，经纬度坐标 (x, y)
      - keywords: 由 (NAME, ADDRESS, CITY, STATE) 四个字段组合而成
    返回:
      - dataset: 一个列表，每个元素为字典，包含键 'id', 'x', 'y', 'keywords'
    """
    df = pd.read_csv(csv_file, sep=";")
    
    # 检查CSV文件是否包含所有必需的列
    required_columns = ['IPEDSID', 'Geo Point', 'NAME', 'ADDRESS', 'CITY', 'STATE']
    for col in required_columns:
        if col not in df.columns:
            raise ValueError(f"CSV文件缺少必需的列: {col}")
    
    dataset = []
    for index, row in df.iterrows():
        # 检查必需字段是否为空或缺失
        skip = False
        for col in required_columns:
            if pd.isnull(row[col]) or str(row[col]).strip() == "":
                print(f"Warning: 第 {index} 行字段 {col} 为空，跳过该行。")
                skip = True
                break
        if skip:
            continue

        uni_id = row['IPEDSID']
        geo_point = row['Geo Point']
        # 假设 'Geo Point' 格式为 "lat, lon"
        try:
            lat_str, lon_str = [s.strip() for s in str(geo_point).split(',')]
            lat = float(lat_str)
            lon = float(lon_str)
        except Exception as e:
            raise ValueError(f"在处理第 {index} 行的 'Geo Point' 字段时出错: {geo_point}") from e
        
        # 将 (NAME, ADDRESS, CITY, STATE) 四个字段组合为关键词集合（这里直接拼接成字符串）
        keywords = f"{row['NAME']} {row['ADDRESS']} {row['CITY']} {row['STATE']}"
        
        # 构造符合 Setup 接口要求的记录（三元组形式）
        record = {
            'id': uni_id,
            'x': lat,
            'y': lon,
            'keywords': keywords
            # 如果后续需要GBF编码后的结果，可在这里预留位置或进行编码
        }
        dataset.append(record)
    return dataset
