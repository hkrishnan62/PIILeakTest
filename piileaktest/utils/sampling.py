"""Utility functions for sampling datasets."""

import pandas as pd
from typing import Literal


def sample_dataframe(
    df: pd.DataFrame,
    mode: Literal["head", "random", "full"] = "head",
    rows: int = 1000
) -> pd.DataFrame:
    """
    Sample a DataFrame according to specified strategy.
    
    Args:
        df: Input DataFrame
        mode: Sampling mode - 'head', 'random', or 'full'
        rows: Number of rows to sample
        
    Returns:
        Sampled DataFrame
    """
    if mode == "full" or len(df) <= rows:
        return df
    elif mode == "head":
        return df.head(rows)
    elif mode == "random":
        return df.sample(n=min(rows, len(df)), random_state=42)
    else:
        raise ValueError(f"Unknown sampling mode: {mode}")
