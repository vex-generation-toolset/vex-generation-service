# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import List

from graph import Call, Graph


@lru_cache(maxsize=None)
def load_graph(filename: str | Path) -> Graph:
    """Load the graph from the file
    We are using lru cache to cache the graph object

    Args:
        filename: path to callgraph

    Returns:
        Graph
    """
    return Graph(filename=filename)


@dataclass
class Package:
    """Package

    Attributes:
        purl: package purl
        callgraph: path to package callgraph json file
        reachable_paths: reachable paths found after analysis
        unreachable_paths: unreachable paths from unaffected package to last affected package in chain
        reachable: does the bug reach this package
    """

    purl: str
    callgraph: str
    reachable_paths: List[List[Call]] = field(default_factory=list)
    unreachable_paths: List[List[Call]] = field(default_factory=list)
    reachable: bool = False
