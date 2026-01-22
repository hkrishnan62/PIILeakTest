"""Data lineage flow loader."""

from typing import List, Dict, Set
from piileaktest.models import LineageEdge, SuiteConfig


def load_lineage_graph(config: SuiteConfig) -> Dict[str, List[str]]:
    """
    Load lineage graph from suite configuration.

    Returns adjacency list representation: dataset_name -> [downstream_datasets]

    Args:
        config: Suite configuration with lineage edges

    Returns:
        Dictionary mapping source datasets to list of target datasets
    """
    graph: Dict[str, List[str]] = {}

    for edge in config.lineage:
        if edge.source not in graph:
            graph[edge.source] = []
        graph[edge.source].append(edge.target)

    return graph


def get_upstream_datasets(dataset_name: str, config: SuiteConfig) -> List[str]:
    """
    Get all upstream (source) datasets for a given dataset.

    Args:
        dataset_name: Name of the target dataset
        config: Suite configuration with lineage edges

    Returns:
        List of upstream dataset names
    """
    upstream = []
    for edge in config.lineage:
        if edge.target == dataset_name:
            upstream.append(edge.source)
    return upstream


def get_downstream_datasets(dataset_name: str, config: SuiteConfig) -> List[str]:
    """
    Get all downstream (target) datasets for a given dataset.

    Args:
        dataset_name: Name of the source dataset
        config: Suite configuration with lineage edges

    Returns:
        List of downstream dataset names
    """
    downstream = []
    for edge in config.lineage:
        if edge.source == dataset_name:
            downstream.append(edge.target)
    return downstream


def get_all_lineage_edges(config: SuiteConfig) -> List[LineageEdge]:
    """
    Get all lineage edges from configuration.

    Args:
        config: Suite configuration

    Returns:
        List of LineageEdge objects
    """
    return config.lineage


def validate_lineage_references(config: SuiteConfig) -> List[str]:
    """
    Validate that all lineage edges reference existing datasets.

    Args:
        config: Suite configuration

    Returns:
        List of error messages (empty if valid)
    """
    dataset_names = {ds.name for ds in config.datasets}
    errors = []

    for edge in config.lineage:
        if edge.source not in dataset_names:
            errors.append(f"Lineage edge references unknown source dataset: {edge.source}")
        if edge.target not in dataset_names:
            errors.append(f"Lineage edge references unknown target dataset: {edge.target}")

    return errors
