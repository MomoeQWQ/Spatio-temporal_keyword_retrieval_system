"""Core APIs for the secure spatio-textual search demo."""

from .indexing import build_index_from_csv, save_index_artifacts, load_index_artifacts
from .query import (
    QueryPlan,
    prepare_query_plan,
    combine_csp_responses,
    combine_sparse_token_vectors,
    decrypt_matches,
    run_fast_preview_verification,
    run_fx_hmac_verification,
    select_sentinel_positions,
)
from .expansion_client import prepare_query_plan_with_expansion, ExpandedQueryPlan
from .query_expansion import expand_query_keywords, ExpansionResult
from .result_ranking import rank_results_by_priority, RankingWeights
from .candidate_index import (
    CandidateIndex,
    CandidateSelection,
    build_candidate_index,
    build_candidate_index_from_csv,
)

__all__ = [
    'build_index_from_csv',
    'save_index_artifacts',
    'load_index_artifacts',
    'QueryPlan',
    'prepare_query_plan',
    'prepare_query_plan_with_expansion',
    'ExpandedQueryPlan',
    'combine_csp_responses',
    'combine_sparse_token_vectors',
    'decrypt_matches',
    'run_fast_preview_verification',
    'run_fx_hmac_verification',
    'select_sentinel_positions',
    'expand_query_keywords',
    'ExpansionResult',
    'rank_results_by_priority',
    'RankingWeights',
    'CandidateIndex',
    'CandidateSelection',
    'build_candidate_index',
    'build_candidate_index_from_csv',
]
