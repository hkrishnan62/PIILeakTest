"""Graph tracing utilities for finding leakage paths."""

from typing import List, Optional, Set, Dict
from piileaktest.models import SuiteConfig, LineageEdge, PIIType


def find_path_to_source(
    target_dataset: str,
    config: SuiteConfig,
) -> List[List[str]]:
    """
    Find all paths from source datasets to the target dataset.

    Uses BFS to find all paths through the lineage graph.

    Args:
        target_dataset: The dataset to find paths to
        config: Suite configuration with lineage

    Returns:
        List of paths, where each path is a list of dataset names
    """
    # Build reverse graph (target -> sources)
    reverse_graph: Dict[str, List[str]] = {}
    for edge in config.lineage:
        if edge.target not in reverse_graph:
            reverse_graph[edge.target] = []
        reverse_graph[edge.target].append(edge.source)

    # Find all paths using DFS
    paths = []

    def dfs(current: str, path: List[str], visited: Set[str]):
        """Depth-first search to find all paths."""
        if current in visited:
            return  # Avoid cycles

        path = path + [current]
        visited = visited | {current}

        # If no upstream, this is a source - record the path
        if current not in reverse_graph or not reverse_graph[current]:
            paths.append(list(reversed(path)))  # Reverse to show source -> target
            return

        # Recurse to upstream datasets
        for upstream in reverse_graph[current]:
            dfs(upstream, path, visited)

    dfs(target_dataset, [], set())
    return paths


def trace_pii_leakage_path(
    pii_type: PIIType,
    target_dataset: str,
    config: SuiteConfig,
) -> Optional[List[str]]:
    """
    Trace the most likely path that a PII type took to reach the target.

    Args:
        pii_type: The PII type that leaked
        target_dataset: The dataset where leakage was detected
        config: Suite configuration

    Returns:
        List of dataset names showing the leakage path, or None if no path found
    """
    paths = find_path_to_source(target_dataset, config)

    if not paths:
        return None

    # For now, return the shortest path
    # In a more sophisticated implementation, we could analyze policies
    # to find the most likely culprit
    shortest_path = min(paths, key=len)
    return shortest_path


def get_all_sources(config: SuiteConfig) -> List[str]:
    """
    Get all source datasets (those with no upstream dependencies).

    Args:
        config: Suite configuration

    Returns:
        List of source dataset names
    """
    all_targets = {edge.target for edge in config.lineage}
    all_datasets = {ds.name for ds in config.datasets}

    # Sources are datasets that are never targets
    sources = all_datasets - all_targets
    return list(sources)


def get_all_sinks(config: SuiteConfig) -> List[str]:
    """
    Get all sink datasets (those with no downstream dependencies).

    Args:
        config: Suite configuration

    Returns:
        List of sink dataset names
    """
    all_sources = {edge.source for edge in config.lineage}
    all_datasets = {ds.name for ds in config.datasets}

    # Sinks are datasets that are never sources
    sinks = all_datasets - all_sources
    return list(sinks)


def detect_cycles(config: SuiteConfig) -> List[List[str]]:
    """
    Detect cycles in the lineage graph.

    Args:
        config: Suite configuration

    Returns:
        List of cycles, where each cycle is a list of dataset names
    """
    # Build adjacency list
    graph: Dict[str, List[str]] = {}
    for edge in config.lineage:
        if edge.source not in graph:
            graph[edge.source] = []
        graph[edge.source].append(edge.target)

    cycles = []
    visited = set()
    rec_stack = set()

    def dfs(node: str, path: List[str]):
        """DFS to detect cycles."""
        visited.add(node)
        rec_stack.add(node)
        path = path + [node]

        if node in graph:
            for neighbor in graph[node]:
                if neighbor not in visited:
                    dfs(neighbor, path)
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycles.append(path[cycle_start:] + [neighbor])

        rec_stack.remove(node)

    for dataset in graph:
        if dataset not in visited:
            dfs(dataset, [])

    return cycles
