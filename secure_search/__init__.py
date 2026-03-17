"""Core APIs for the secure spatio-textual search demo."""

from .indexing import build_index_from_csv, save_index_artifacts, load_index_artifacts
from .query import (
    QueryPlan,
    prepare_query_plan,
    combine_csp_responses,
    decrypt_matches,
    run_fx_hmac_verification,
)
from .expansion_client import prepare_query_plan_with_expansion, ExpandedQueryPlan
from .query_expansion import expand_query_keywords, ExpansionResult
from .result_ranking import rank_results_by_priority, RankingWeights

__all__ = [
    'build_index_from_csv',
    'save_index_artifacts',
    'load_index_artifacts',
    'QueryPlan',
    'prepare_query_plan',
    'prepare_query_plan_with_expansion',
    'ExpandedQueryPlan',
    'combine_csp_responses',
    'decrypt_matches',
    'run_fx_hmac_verification',
    'expand_query_keywords',
    'ExpansionResult',
    'rank_results_by_priority',
    'RankingWeights',
]
