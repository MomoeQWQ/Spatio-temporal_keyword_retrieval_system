"""High-level helper to integrate query expansion into secure search."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Sequence

from core.QueryUtils import tokenize_normalized

from .query import QueryPlan, prepare_query_plan
from .query_expansion import ExpansionCallable, ExpansionResult, expand_query_keywords


@dataclass
class ExpandedQueryPlan:
    plans: List[QueryPlan]
    query_texts: List[str]
    expansion: ExpansionResult
    original_query: str

    @property
    def plan(self) -> QueryPlan:
        return self.plans[0]


def _split_query(query_text: str) -> tuple[str, str]:
    if "R:" in query_text:
        prefix, rest = query_text.split("R:", 1)
        prefix = prefix.strip()
        if prefix.endswith(";"):
            prefix = prefix[:-1]
        spatial_suffix = f"; R:{rest}"
    else:
        prefix = query_text.strip()
        spatial_suffix = ""
    return prefix, spatial_suffix


def _build_query(tokens: Sequence[str], spatial_suffix: str) -> str:
    prefix = " ".join(tokens).strip()
    if spatial_suffix:
        return f"{prefix}{spatial_suffix}"
    return prefix


def prepare_query_plan_with_expansion(
    query_text: str,
    aui: dict,
    config: dict,
    *,
    llm_callable: ExpansionCallable | None = None,
    max_terms: int = 5,
) -> ExpandedQueryPlan:
    keyword_segment, spatial_suffix = _split_query(query_text)
    keyword_tokens_norm = tokenize_normalized(keyword_segment)
    expansion = expand_query_keywords(
        keyword_tokens_norm,
        llm_callable=llm_callable,
        max_terms=max_terms,
    )

    plans: List[QueryPlan] = []
    query_texts: List[str] = []

    # Base query
    base_query = query_text.strip()
    plans.append(prepare_query_plan(base_query, aui, config))
    query_texts.append(base_query)

    # Generate additional queries by replacing each token with its expansions
    seen_queries = {base_query}
    for idx, token in enumerate(expansion.original_tokens):
        for synonym in expansion.token_expansions.get(token, []):
            if not synonym or synonym == token:
                continue
            tokens_copy = expansion.original_tokens.copy()
            tokens_copy[idx] = synonym
            new_query = _build_query(tokens_copy, spatial_suffix)
            if new_query in seen_queries:
                continue
            seen_queries.add(new_query)
            plans.append(prepare_query_plan(new_query, aui, config))
            query_texts.append(new_query)

    return ExpandedQueryPlan(
        plans=plans,
        query_texts=query_texts,
        expansion=expansion,
        original_query=query_text,
    )
