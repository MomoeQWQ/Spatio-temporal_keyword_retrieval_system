"""Priority ranking utilities for expanded-query search results."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Set, Tuple

from core.QueryUtils import normalize_token, tokenize_normalized


@dataclass(frozen=True)
class RankingWeights:
    base_query_hit: float = 80.0
    expansion_query_hit: float = 22.0
    exact_name_token: float = 16.0
    exact_meta_token: float = 6.0
    synonym_name_token: float = 8.0
    synonym_meta_token: float = 3.0
    exact_coverage: float = 22.0
    synonym_coverage: float = 10.0
    ordered_phrase_bonus: float = 14.0
    spatial_bonus: float = 6.0


def _split_keyword_segment(query_text: str) -> str:
    if "R:" in query_text:
        return query_text.split("R:", 1)[0]
    return query_text


def _extract_range(query_text: str) -> Tuple[float, float, float, float] | None:
    if "R:" not in query_text:
        return None
    try:
        _, rng = query_text.split("R:", 1)
        parts = rng.replace(";", " ").replace(",", " ").split()
        if len(parts) < 4:
            return None
        lat_min, lon_min, lat_max, lon_max = map(float, parts[:4])
        return (min(lat_min, lat_max), min(lon_min, lon_max), max(lat_min, lat_max), max(lon_min, lon_max))
    except Exception:
        return None


def _safe_float(value) -> float | None:
    try:
        if value is None:
            return None
        text = str(value).strip()
        if not text or text.upper() == "NOT AVAILABLE":
            return None
        return float(text)
    except Exception:
        return None


def _point_in_range(record: dict, bbox: Tuple[float, float, float, float] | None) -> bool:
    if bbox is None:
        return False
    lat_min, lon_min, lat_max, lon_max = bbox
    lat = _safe_float(record.get("LATITUDE", record.get("Latitude")))
    lon = _safe_float(record.get("LONGITUDE", record.get("Longitude")))
    if lat is None or lon is None:
        geo_point = str(record.get("Geo Point", "")).strip()
        vals = re.findall(r"-?\d+(?:\.\d+)?", geo_point)
        if len(vals) >= 2:
            lat = _safe_float(vals[0])
            lon = _safe_float(vals[1])
    if lat is None or lon is None:
        return False
    return lat_min <= lat <= lat_max and lon_min <= lon <= lon_max


def _ordered_subsequence_exists(sequence: Sequence[str], subseq: Sequence[str]) -> bool:
    if not subseq:
        return False
    j = 0
    for token in sequence:
        if token == subseq[j]:
            j += 1
            if j == len(subseq):
                return True
    return False


def _normalize_tokens(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    for v in values:
        n = normalize_token(v)
        if n:
            out.append(n)
    return out


def rank_results_by_priority(
    query_text: str,
    records: Sequence[dict],
    *,
    expanded_tokens: Iterable[str] | None = None,
    hit_sources: Dict[str, Set[int]] | None = None,
    weights: RankingWeights = RankingWeights(),
) -> List[dict]:
    """
    Rank result records with platform-style priority weights.

    Parameters
    ----------
    query_text:
        Raw user query (optional "R:" spatial suffix allowed).
    records:
        Candidate records to rank.
    expanded_tokens:
        Expansion/synonym tokens (already normalized or raw).
    hit_sources:
        Mapping record ID -> subquery index set. Index 0 is base query.
    weights:
        Scoring weights.
    """

    keyword_tokens = tokenize_normalized(_split_keyword_segment(query_text))
    exact_set = set(keyword_tokens)
    expanded_set = set(_normalize_tokens(expanded_tokens or []))
    synonym_set = expanded_set.difference(exact_set)
    bbox = _extract_range(query_text)

    ranked: List[dict] = []
    for rec in records:
        rid = str(rec.get("IPEDSID", ""))
        name_text = str(rec.get("NAME", ""))
        meta_text = " ".join(
            str(rec.get(k, ""))
            for k in ("ADDRESS", "CITY", "STATE")
        )
        name_tokens = tokenize_normalized(name_text)
        meta_tokens = tokenize_normalized(meta_text)
        all_tokens = set(name_tokens) | set(meta_tokens)

        score = 0.0

        source_set = hit_sources.get(rid, set()) if hit_sources else set()
        if 0 in source_set:
            score += weights.base_query_hit
        if source_set:
            score += weights.expansion_query_hit * max(0, len(source_set) - (1 if 0 in source_set else 0))

        exact_name = exact_set & set(name_tokens)
        exact_meta = exact_set & set(meta_tokens)
        synonym_name = synonym_set & set(name_tokens)
        synonym_meta = synonym_set & set(meta_tokens)

        score += weights.exact_name_token * len(exact_name)
        score += weights.exact_meta_token * len(exact_meta)
        score += weights.synonym_name_token * len(synonym_name)
        score += weights.synonym_meta_token * len(synonym_meta)

        if exact_set:
            score += weights.exact_coverage * (len(exact_set & all_tokens) / len(exact_set))
        if synonym_set:
            score += weights.synonym_coverage * (len(synonym_set & all_tokens) / len(synonym_set))

        if keyword_tokens and _ordered_subsequence_exists(name_tokens, keyword_tokens):
            score += weights.ordered_phrase_bonus

        if _point_in_range(rec, bbox):
            score += weights.spatial_bonus

        ranked.append(
            {
                "record": rec,
                "score": round(score, 4),
                "source_hits": len(source_set),
                "base_hit": (0 in source_set),
            }
        )

    ranked.sort(
        key=lambda x: (
            -x["score"],
            -int(x["base_hit"]),
            -x["source_hits"],
            str(x["record"].get("NAME", "")),
        )
    )
    return ranked
