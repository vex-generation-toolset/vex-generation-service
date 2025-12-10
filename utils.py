# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from graph import Call, Graph


@lru_cache(maxsize=16)
def load_graph(filename: str | Path) -> Graph:
    """Load the graph from the file
    We are using lru cache to cache the graph object

    Args:
        filename: path to callgraph

    Returns:
        Graph
    """
    return Graph(filename=filename)


def name(purl: str) -> str:
    return purl.split("/")[-1]


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
    reachable_paths: list[list[Call]] = field(default_factory=list)
    unreachable_paths: list[list[Call]] = field(default_factory=list)
    reachable: bool = False


class CustomEncoder(json.JSONEncoder):
    """A custom json encoder that uses `to_json` attribute of objects"""

    def default(self, o):
        # If object has a custom JSON representation, use it
        if hasattr(o, "to_json"):
            return o.to_json()
        # Let dataclasses serialize naturally (their __dict__)
        if hasattr(o, "__dict__"):
            return o.__dict__
        return super().default(o)
