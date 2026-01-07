# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
from collections import defaultdict
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict

from vex_generation_service.function import Function
from vex_generation_service.utils import Call, is_candidate, score_candidate


@dataclass(frozen=True)
class Package:
    """A package

    Attributes:
        path: Path of the package
        isRoot: Is this package the root of the callgraph?
        module: Index of the module this package is a part of
        name: Name of the package
        isStandardLibrary: Is this package a part of the standard library?
    """

    path: str
    isRoot: bool
    module: int
    name: str
    isStandardLibrary: bool


@dataclass(frozen=True)
class Module:
    """A module

    Attributes:
        name: Name of the module
        version: Module version
        hash: Module hash
    """

    name: str
    version: str
    hash: str


class Graph:
    """A function call graph

    Attributes:
        language: Language of the packages
        functions: list of functions
        calls: list of calls
        packages: list of packages
        modules: list of modules
        callers: Callee to callers memo for faster access
    """

    def __init__(self, filename: str | Path):
        """Initialize the call graph

        Args:
            filename: Path to the call graph json
        """
        self.language: str
        self.functions: list[Function]
        self.calls: list[Call]
        self.packages: list[Package]
        self.modules: list[Module]
        self.callers: Dict[int, list[int]] = defaultdict(list)
        self.call_map: Dict[tuple[int, int], int] = {}
        self.best_candidate: Dict[str, int | None] = {}

        self.load(filename)

    def load(self, filename: str | Path):
        """Load the graph from the file

        Args:
            filename: Path to the call graph json
        """

        def embed_function(c) -> Call:
            """Embed function names

            Args:
                c (dict[str, Any]): call json object

            Returns:
                Call object with embeded function name
            """
            caller = c.get("caller")
            callee = c.get("callee")
            return Call(
                callerName=self.functions[caller].name,
                calleeName=self.functions[callee].name,
                **c,
            )

        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        language = data.get("language")
        self.language = language

        modules = data.get("modules")
        self.modules = [Module(**m) for m in modules]

        packages = data.get("packages")
        self.packages = [Package(**p) for p in packages]

        functions = data.get("functions")
        self.functions = [Function(**f) for f in functions]

        calls = data.get("calls")
        self.calls = [embed_function(c) for c in calls]

        for i, call in enumerate(self.calls):
            self.callers[call.callee].append(call.caller)
            self.call_map[(call.caller, call.callee)] = i
        f.close()

    def find_sinks(self, functions: list[str] | list[Function]) -> list[int]:
        """Find sinks from functions

        Args:
            functions: A list of qualified function names or function objects

        Returns:
            Unique list of function indices
        """

        sinks: list[int] = []
        for function in functions:
            best_candidate = self.get_best_candidate(function)
            if best_candidate is not None:
                sinks.append(best_candidate)

        return sinks

    def get_best_candidate(self, function: str | Function) -> int | None:
        """Get the best candidate for a function name or object

        Args:
            function: Function name or object
        """

        match function:
            case str():
                function = function.strip(" ").replace("#", ".")
            case Function():
                function = function.name.strip(" ").replace("#", ".")

        if function in self.best_candidate:
            return self.best_candidate[function]

        candidates: list[int] = [
            i for i, f in enumerate(self.functions) if is_candidate(f.name, function)
        ]

        best_score = -1
        best_candidate = None
        for c in candidates:
            candidate = self.functions[c]
            if candidate.name == function:
                self.best_candidate[function] = c
                return c
            score = score_candidate(candidate, function)
            if score > best_score:
                best_score = score
                best_candidate = c

        self.best_candidate[function] = best_candidate
        return best_candidate

    def get_functions(self, indices: list[int]) -> list[Function]:
        """Get a lisf of functions from their indices

        Args:
            indices: list of indices

        Returns:
            list of functions
        """
        return [self.functions[i] for i in indices]

    def get_other_functions(self, indices: list[int]) -> list[Function]:
        """Get a lisf of functions not in the indices

        Args:
            indices: list of indices

        Returns:
            list of other functions
        """
        return [
            f
            for i, f in enumerate(self.functions)
            if i not in indices and f.packageIndex != -1
        ]

    def find_call_chains(
        self, sinks: list[int], max_call_chains: int = 0
    ) -> tuple[list[int], list[list[int]]]:
        """Find call chains to sinks

        Args:
            sinks: indices of sink functions
            max_paths: maximum call chains to keep. default = 0 means no limit

        Returns:
            affected functions indices, call chains
        """
        visited: Dict[int, bool] = {}
        chains: list[list[int]] = []

        def dfs(sink: int) -> list[list[int]]:
            """Depth first search from sink to callers

            Args:
                sink: sink function index

            Returns:
                list of call chains
            """
            visited[sink] = True
            callers = self.callers.get(sink, [])
            if len(callers) < 1:
                return [[]]

            all_chains: list[list[int]] = [[]]
            for c in callers:
                if c in visited or self.functions[c].packageIndex == -1:
                    continue
                prefix_call_chains = dfs(c)
                for call_chain in prefix_call_chains:
                    all_chains.append(call_chain + [self.call_map[(c, sink)]])
            return all_chains

        for s in sinks:
            if max_call_chains > 0 and len(chains) >= max_call_chains:
                break

            new_chains = dfs(s)
            if max_call_chains > 0:
                needed = max_call_chains - len(chains)
                chains.extend(new_chains[:needed])
            else:
                chains.extend(new_chains)

        return list(visited.keys()), [chain for chain in chains if len(chain) > 0]


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
