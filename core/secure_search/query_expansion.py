"""Utilities for client-side query expansion using LLMs or heuristic fallbacks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Sequence, Set

from core.QueryUtils import normalize_token

DEFAULT_FEW_SHOT_PROMPT = """\
You are a search query expansion assistant. Generate a short comma-separated list \
of synonyms or closely related search terms for the following user keyword that \
will help retrieve more matching locations.

Examples:
User term: car park
Expansions: parking garage, parking lot, vehicle storage

User term: pharmacy
Expansions: drugstore, chemist, apothecary

User term: {keyword}
Expansions:
"""

FALLBACK_SYNONYMS: Dict[str, Set[str]] = {
    "UNIVERSITY": {"COLLEGE", "CAMPUS", "INSTITUTE"},
    "COLLEGE": {"UNIVERSITY", "ACADEMY", "SCHOOL"},
    "ENGINEERING": {"TECHNOLOGY", "TECH", "STEM"},
    "MEDICAL": {"HEALTH", "HOSPITAL"},
    "BUSINESS": {"COMMERCE", "ENTERPRISE"},
    "DINER": {"RESTAURANT", "CAFE", "EATERY"},
    "PARK": {"GARDEN", "RESERVE"},
    "LIBRARY": {"ARCHIVE", "LEARNING CENTER"},
}


def _parse_terms(raw: str, max_terms: int | None = None) -> List[str]:
    tokens: List[str] = []
    for chunk in raw.replace("\n", ",").split(","):
        term = normalize_token(chunk.strip())
        if term:
            tokens.append(term)
    if max_terms is not None:
        tokens = tokens[:max_terms]
    return tokens


ExpansionCallable = Callable[[str], str]


@dataclass
class ExpansionResult:
    original_tokens: List[str]
    expanded_tokens: List[str]
    added_tokens: List[str]
    token_expansions: Dict[str, List[str]]
    raw_responses: Dict[str, str]


def expand_keywords_with_llm(
    keyword_tokens: Sequence[str],
    llm_callable: ExpansionCallable,
    *,
    few_shot_prompt: str = DEFAULT_FEW_SHOT_PROMPT,
    max_terms: int = 5,
) -> ExpansionResult:
    raw_responses: Dict[str, str] = {}
    token_expansion_map: Dict[str, List[str]] = {}
    expanded: Set[str] = set()
    for token in keyword_tokens:
        prompt = few_shot_prompt.format(keyword=token.lower())
        response = llm_callable(prompt)
        raw_responses[token] = response
        terms = _parse_terms(response, max_terms=max_terms)
        token_expansion_map[token] = terms
        expanded.update(terms)
    original_norm = [normalize_token(tok) for tok in keyword_tokens]
    expanded.update(original_norm)
    added = sorted(expanded.difference(original_norm))
    return ExpansionResult(
        original_tokens=list(original_norm),
        expanded_tokens=sorted(expanded),
        added_tokens=added,
        token_expansions=token_expansion_map,
        raw_responses=raw_responses,
    )


def expand_keywords_fallback(
    keyword_tokens: Sequence[str],
    *,
    synonyms_map: Dict[str, Iterable[str]] | None = None,
    max_terms: int = 5,
) -> ExpansionResult:
    synonyms = synonyms_map or FALLBACK_SYNONYMS
    token_expansion_map: Dict[str, List[str]] = {}
    expanded: Set[str] = set()
    raw: Dict[str, str] = {}
    original_norm = [normalize_token(tok) for tok in keyword_tokens]
    for token in original_norm:
        # Sort for deterministic behavior (fallback map may contain sets).
        expansion_src = sorted({normalize_token(term) for term in synonyms.get(token, []) if normalize_token(term)})
        expansion = expansion_src[:max(0, int(max_terms))]
        expansion = [term for term in expansion if term]
        raw[token] = ", ".join(expansion)
        token_expansion_map[token] = expansion
        expanded.update(expansion)
    expanded.update(original_norm)
    added = sorted(expanded.difference(original_norm))
    return ExpansionResult(
        original_tokens=list(original_norm),
        expanded_tokens=sorted(expanded),
        added_tokens=added,
        token_expansions=token_expansion_map,
        raw_responses=raw,
    )


def expand_query_keywords(
    keyword_tokens: Sequence[str],
    *,
    llm_callable: ExpansionCallable | None = None,
    few_shot_prompt: str = DEFAULT_FEW_SHOT_PROMPT,
    max_terms: int = 5,
    fallback_synonyms: Dict[str, Iterable[str]] | None = None,
) -> ExpansionResult:
    if llm_callable is not None:
        try:
            return expand_keywords_with_llm(
                keyword_tokens,
                llm_callable,
                few_shot_prompt=few_shot_prompt,
                max_terms=max_terms,
            )
        except Exception:
            pass
    return expand_keywords_fallback(
        keyword_tokens,
        synonyms_map=fallback_synonyms,
        max_terms=max_terms,
    )
