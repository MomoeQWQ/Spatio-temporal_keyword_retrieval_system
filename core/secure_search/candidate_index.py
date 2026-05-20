"""RAPQ candidate index: rarity-aware progressive pruning for query acceleration."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Sequence

from core import prepare_dataset
from core.QueryUtils import tokenize_normalized


def _split_query(query_text: str) -> tuple[str, str]:
    if "R:" in query_text:
        prefix, rest = query_text.split("R:", 1)
        return prefix.strip(), rest.strip()
    return query_text.strip(), ""


def _extract_spatial_cells(query_text: str, config: dict) -> List[str]:
    cells: List[str] = []
    if "R:" not in query_text:
        return cells
    try:
        _, rng = query_text.split("R:", 1)
        parts = rng.replace(";", " ").replace(",", " ").split()
        if len(parts) < 4:
            return cells
        lat_min, lon_min, lat_max, lon_max = map(float, parts[:4])
        grid = config.get("spatial_grid", {})
        lat_step = float(grid.get("cell_size_lat", 0.5))
        lon_step = float(grid.get("cell_size_lon", 0.5))
        r0 = math.floor(lat_min / lat_step)
        r1 = math.floor(lat_max / lat_step)
        c0 = math.floor(lon_min / lon_step)
        c1 = math.floor(lon_max / lon_step)
        for r in range(min(r0, r1), max(r0, r1) + 1):
            for c in range(min(c0, c1), max(c0, c1) + 1):
                cells.append(f"CELL:R{r}_C{c}")
    except Exception:
        return []
    return cells


def _iter_set_bits(bitset: int, limit: int | None = None) -> List[int]:
    out: List[int] = []
    while bitset:
        lsb = bitset & -bitset
        idx = lsb.bit_length() - 1
        out.append(idx)
        if limit is not None and len(out) >= limit:
            break
        bitset ^= lsb
    return out


@dataclass
class CandidateSelection:
    positions: List[int]
    keyword_tokens: List[str]
    spatial_tokens: List[str]
    sorted_keywords: List[str]
    total_records: int

    @property
    def candidate_count(self) -> int:
        return len(self.positions)

    @property
    def candidate_ratio(self) -> float:
        if self.total_records <= 0:
            return 0.0
        return len(self.positions) / float(self.total_records)


@dataclass
class CandidateIndex:
    n_records: int
    keyword_postings: Dict[str, int]
    spatial_postings: Dict[str, int]
    keyword_df: Dict[str, int]

    def select_candidates(
        self,
        query_text: str,
        config: dict,
        *,
        max_candidates: int | None = None,
    ) -> CandidateSelection:
        keyword_segment, _ = _split_query(query_text)
        kw_tokens = tokenize_normalized(keyword_segment)
        spa_tokens = _extract_spatial_cells(query_text, config)

        all_rows = (1 << self.n_records) - 1 if self.n_records > 0 else 0
        if kw_tokens:
            sorted_kw = sorted(kw_tokens, key=lambda t: self.keyword_df.get(t, self.n_records + 1))
            bits = all_rows
            for token in sorted_kw:
                bits &= self.keyword_postings.get(token, 0)
                if bits == 0:
                    break
        else:
            sorted_kw = []
            bits = all_rows

        if spa_tokens:
            spatial_bits = 0
            for cell in spa_tokens:
                spatial_bits |= self.spatial_postings.get(cell, 0)
            bits &= spatial_bits

        if max_candidates is not None and max_candidates <= 0:
            max_candidates = None
        positions = _iter_set_bits(bits, limit=max_candidates)
        return CandidateSelection(
            positions=positions,
            keyword_tokens=kw_tokens,
            spatial_tokens=spa_tokens,
            sorted_keywords=sorted_kw,
            total_records=self.n_records,
        )


def build_candidate_index(records: Sequence[dict], config: dict) -> CandidateIndex:
    keyword_postings: Dict[str, int] = {}
    spatial_postings: Dict[str, int] = {}
    grid = config.get("spatial_grid", {})
    lat_step = float(grid.get("cell_size_lat", 0.5))
    lon_step = float(grid.get("cell_size_lon", 0.5))

    for row_idx, rec in enumerate(records):
        row_bit = 1 << row_idx
        kw_tokens = set(tokenize_normalized(str(rec.get("keywords", ""))))
        for tok in kw_tokens:
            keyword_postings[tok] = keyword_postings.get(tok, 0) | row_bit
        try:
            lat = float(rec.get("x"))
            lon = float(rec.get("y"))
            r = math.floor(lat / lat_step)
            c = math.floor(lon / lon_step)
            cell = f"CELL:R{r}_C{c}"
            spatial_postings[cell] = spatial_postings.get(cell, 0) | row_bit
        except Exception:
            pass

    keyword_df = {tok: bits.bit_count() for tok, bits in keyword_postings.items()}
    return CandidateIndex(
        n_records=len(records),
        keyword_postings=keyword_postings,
        spatial_postings=spatial_postings,
        keyword_df=keyword_df,
    )


def build_candidate_index_from_csv(csv_path: str, config: dict) -> CandidateIndex:
    records = prepare_dataset.load_and_transform(csv_path)
    return build_candidate_index(records, config)
