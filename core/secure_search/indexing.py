"""Utilities for building, saving, and loading authenticated indexes."""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

import pickle

from core.config_loader import load_config
from core import prepare_dataset
from core.convert_dataset import convert_dataset
from core.SetupProcess import Setup

IndexArtifacts = Tuple[dict, tuple]


def build_index_from_csv(csv_path: str, config_path: str) -> IndexArtifacts:
    """Construct the authenticated index and key tuple from a CSV dataset."""
    cfg = load_config(config_path)
    dict_list = prepare_dataset.load_and_transform(csv_path)
    db = convert_dataset(dict_list, cfg)
    return Setup(db, cfg)


def save_index_artifacts(aui: dict, keys: tuple, output_dir: str | Path) -> Tuple[Path, Path]:
    """Persist the authenticated index and keys to disk and return their paths."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    aui_path = out_dir / "aui.pkl"
    key_path = out_dir / "K.pkl"
    with aui_path.open("wb") as f:
        pickle.dump(aui, f)
    with key_path.open("wb") as f:
        pickle.dump(keys, f)
    return aui_path, key_path


def load_index_artifacts(aui_path: str | Path, key_path: str | Path) -> IndexArtifacts:
    """Load the authenticated index and keys from disk."""
    with Path(aui_path).open("rb") as f:
        aui = pickle.load(f)
    with Path(key_path).open("rb") as f:
        keys = pickle.load(f)
    return aui, keys
