"""
Generate a conceptual diagram that illustrates how the project balances
spatio-temporal text data privacy protection with efficient encrypted search.
"""

import os

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle


def add_box(ax, xy, width, height, text, facecolor, edgecolor="#1b2836", fontsize=12):
    """Helper to add a rounded box with centered text."""
    box = FancyBboxPatch(
        xy,
        width,
        height,
        boxstyle="round,pad=0.35",
        linewidth=2,
        facecolor=facecolor,
        edgecolor=edgecolor,
    )
    ax.add_patch(box)
    ax.text(
        xy[0] + width / 2,
        xy[1] + height / 2,
        text,
        ha="center",
        va="center",
        fontsize=fontsize,
        color="#0f1d2b",
    )


def add_arrow(
    ax,
    start,
    end,
    color="#1b2836",
    arrowstyle="-|>",
    connectionstyle="arc3,rad=0.0",
    mutation_scale=18,
):
    """Draw a directional arrow between two points."""
    arrow = FancyArrowPatch(
        start,
        end,
        arrowstyle=arrowstyle,
        linewidth=2,
        color=color,
        connectionstyle=connectionstyle,
        mutation_scale=mutation_scale,
        shrinkA=6,
        shrinkB=6,
    )
    ax.add_patch(arrow)


def main():
    # Attempt to use a font that supports Chinese characters; fall back gracefully.
    plt.rcParams["font.sans-serif"] = [
        "Microsoft YaHei",
        "SimHei",
        "Source Han Sans CN",
        "Arial Unicode MS",
        "sans-serif",
    ]
    plt.rcParams["axes.unicode_minus"] = False

    fig, ax = plt.subplots(figsize=(13.8, 8.2))
    ax.set_xlim(0, 16)
    ax.set_ylim(0, 9)
    ax.axis("off")

    # Backdrop bands to separate layers.
    bands = [
        {
            "rect": (0.6, 6.6, 14.8, 2.1),
            "color": "#e1f0ff",
            "label": ("隐私保护层", 0.8, 8.3, "#0a3556"),
        },
        {
            "rect": (0.6, 4.2, 14.8, 1.9),
            "color": "#eaf6ff",
            "label": ("协同执行层", 0.8, 5.8, "#0a3f4a"),
        },
        {
            "rect": (0.6, 1.4, 14.8, 1.9),
            "color": "#e7f8f0",
            "label": ("高效检索层", 0.8, 2.9, "#0a4a3c"),
        },
    ]
    for band in bands:
        rect = Rectangle(
            (band["rect"][0], band["rect"][1]),
            band["rect"][2],
            band["rect"][3],
            facecolor=band["color"],
            edgecolor="none",
            alpha=0.55,
        )
        ax.add_patch(rect)
        label_text, label_x, label_y, label_color = band["label"]
        ax.text(label_x, label_y, label_text, fontsize=14, weight="bold", color=label_color)

    box_height = 1.3

    # Top row: privacy-preserving data preparation.
    top_boxes = [
        {
            "xy": (1.2, 7.0),
            "w": 2.8,
            "text": "原始时空文本\n(位置 + 事件描述)",
            "color": "#9ecbff",
        },
        {
            "xy": (4.6, 7.0),
            "w": 3.1,
            "text": "脱敏与分段处理\n匿名化 / 格网编码 / 分词",
            "color": "#b6ddff",
        },
        {
            "xy": (8.4, 7.0),
            "w": 3.4,
            "text": "安全索引构建\nGBF 指纹 + F(x) 掩码 + HMAC 关键字",
            "color": "#d2eaff",
        },
        {
            "xy": (12.2, 7.0),
            "w": 2.8,
            "text": "密文索引分片\n分布式上传至多家 CSP",
            "color": "#bdd4f8",
        },
    ]
    for box_info in top_boxes:
        add_box(
            ax,
            box_info["xy"],
            box_info["w"],
            box_height,
            box_info["text"],
            box_info["color"],
        )

    # Middle row: multi-party secure storage and computation.
    mid_boxes = [
        {
            "xy": (8.6, 4.6),
            "w": 2.8,
            "text": "CSP-1\n密文份额存储\n返回 XOR 份额 + 证明",
            "color": "#c9f0df",
        },
        {
            "xy": (12.0, 4.6),
            "w": 2.8,
            "text": "CSP-2\n密文份额存储\n返回 XOR 份额 + 证明",
            "color": "#c9f0df",
        },
    ]
    for box_info in mid_boxes:
        add_box(
            ax,
            box_info["xy"],
            box_info["w"],
            box_height,
            box_info["text"],
            box_info["color"],
        )

    add_box(
        ax,
        (12.0, 2.0),
        2.8,
        box_height,
        "密文组合与验证\n聚合份额, 解密, FX-HMAC 校验",
        "#a7ddc8",
    )

    # Bottom row: query and retrieval path.
    bottom_boxes = [
        {
            "xy": (1.2, 1.6),
            "w": 2.8,
            "text": "查询发起者\n(应急调度 / 研究人员)",
            "color": "#c9f3e2",
        },
        {
            "xy": (4.6, 1.6),
            "w": 3.1,
            "text": "隐私查询计划\n关键词哈希 + 时空窗口拆分",
            "color": "#dcf8eb",
        },
        {
            "xy": (8.4, 1.6),
            "w": 3.4,
            "text": "安全查询令牌\n密钥派生 / 多方环签名",
            "color": "#dff5e9",
        },
    ]
    for box_info in bottom_boxes:
        add_box(
            ax,
            box_info["xy"],
            box_info["w"],
            box_height,
            box_info["text"],
            box_info["color"],
        )

    add_box(
        ax,
        (12.0, 0.6),
        2.8,
        1.1,
        "输出结果\n可验证命中 + 合规审计日志",
        "#c7ede0",
    )

    # Horizontal flow for data preparation.
    for idx in range(len(top_boxes) - 1):
        current = top_boxes[idx]
        nxt = top_boxes[idx + 1]
        y_center = current["xy"][1] + box_height / 2
        start = (current["xy"][0] + current["w"], y_center)
        end = (nxt["xy"][0], y_center)
        add_arrow(ax, start, end)

    # Arrows from secure index to CSPs.
    secure_box = top_boxes[2]
    shard_box = top_boxes[3]
    secure_center_x = secure_box["xy"][0] + secure_box["w"] / 2
    shard_center_x = shard_box["xy"][0] + shard_box["w"] / 2
    add_arrow(
        ax,
        (secure_center_x, secure_box["xy"][1]),
        (secure_center_x, mid_boxes[0]["xy"][1] + box_height),
        color="#0a3556",
    )
    add_arrow(
        ax,
        (shard_center_x, shard_box["xy"][1]),
        (mid_boxes[1]["xy"][0] + mid_boxes[1]["w"] / 2, mid_boxes[1]["xy"][1] + box_height),
        color="#0a3556",
    )

    # Query flow arrows.
    for idx in range(len(bottom_boxes) - 1):
        current = bottom_boxes[idx]
        nxt = bottom_boxes[idx + 1]
        y_center = current["xy"][1] + box_height / 2
        start = (current["xy"][0] + current["w"], y_center)
        end = (nxt["xy"][0], y_center)
        add_arrow(ax, start, end, color="#0a4a3c")

    # Query tokens distributed to CSPs.
    token_box = bottom_boxes[2]
    token_center_y = token_box["xy"][1] + box_height
    token_center_x = token_box["xy"][0] + 0.6 * token_box["w"]
    add_arrow(
        ax,
        (token_center_x, token_center_y),
        (mid_boxes[0]["xy"][0] + mid_boxes[0]["w"] / 2, mid_boxes[0]["xy"][1]),
        color="#0a4a3c",
        connectionstyle="arc3,rad=0.25",
    )
    add_arrow(
        ax,
        (token_center_x + 0.5, token_center_y),
        (mid_boxes[1]["xy"][0] + mid_boxes[1]["w"] / 2, mid_boxes[1]["xy"][1]),
        color="#0a4a3c",
        connectionstyle="arc3,rad=-0.3",
    )

    # CSP responses to combination node.
    combine_box_xy = (12.0, 2.0)
    combine_center = (combine_box_xy[0] + 1.4, combine_box_xy[1] + box_height)
    for idx, mid_box in enumerate(mid_boxes):
        mid_center = (mid_box["xy"][0] + mid_box["w"] / 2, mid_box["xy"][1])
        add_arrow(
            ax,
            mid_center,
            combine_center,
            color="#0a4a3c",
            connectionstyle="arc3,rad=-0.2" if idx == 0 else "arc3,rad=0.2",
        )

    # Combination to final output.
    add_arrow(
        ax,
        (combine_center[0], combine_box_xy[1]),
        (13.4, 1.7),
        color="#0a4a3c",
    )

    # Callout annotations.
    ax.text(
        2.8,
        5.1,
        "差分隐私 + 格网编码\n确保单条轨迹无法回溯",
        fontsize=11,
        color="#0a3556",
    )
    ax.text(
        4.9,
        2.6,
        "查询保持时空上下文, 仍可高精度命中",
        fontsize=11,
        color="#0a4a3c",
    )

    fig.tight_layout()
    output_path = os.path.join(os.path.dirname(__file__), "privacy_search_solution.png")
    fig.savefig(output_path, dpi=200)
    print(f"Saved diagram to {output_path}")


if __name__ == "__main__":
    main()
