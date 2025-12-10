# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from function import Function


@dataclass
class Site:
    """A function call site

    Attributes:
        filename: file that hosts the call site
        line: line number
        column: column number
        directory: relative directory of the file
    """

    filename: str
    line: int
    column: int
    directory: str


@dataclass
class Call:
    """A function call

    Attributes:
        callSite: The function call site
        caller: Caller function index
        callee: Callee function index
    """

    callSite: Site
    caller: int
    callerName: str
    callee: int
    calleeName: str

    def to_json(self):
        return {
            "caller": self.callerName,
            "callee": self.calleeName,
            "callSite": self.callSite,
        }


@dataclass
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


@dataclass
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
        functions: List of functions
        calls: List of calls
        packages: List of packages
        modules: List of modules
        callers: Callee to callers memo for faster access
    """

    def __init__(self, filename: str | Path):
        """Initialize the call graph

        Args:
            filename: Path to the call graph json
        """
        self.language: str
        self.functions: List[Function]
        self.calls: List[Call]
        self.packages: List[Package]
        self.modules: List[Module]
        self.callers: Dict[int, List[int]] = defaultdict(list)
        self.call_map: Dict[tuple[int, int], int] = {}

        self.load(filename)

    def load(self, filename: str | Path):
        """Load the graph from the file

        Args:
            filename: Path to the call graph json
        """

        def embed_package(f) -> Function:
            """Embed package name inside function object

            Args:
                f (dict[str, Any]): function json object

            Returns:
                Function object with embeded package name
            """
            pkg_idx = f.get("packageIndex")
            return Function(
                package=self.packages[pkg_idx].path if pkg_idx != -1 else "",
                **f,
            )

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
        self.functions = [embed_package(f) for f in functions]

        calls = data.get("calls")
        self.calls = [embed_function(c) for c in calls]

        for i, call in enumerate(self.calls):
            self.callers[call.callee].append(call.caller)
            self.call_map[(call.caller, call.callee)] = i
        f.close()

    def find_sinks(self, functions: List[str] | List[Function]) -> List[int]:
        """Find sinks from functions

        Args:
            functions: A list of qualified function names or function objects

        Returns:
            Unique list of function indices
        """
        return list(set([i for i, f in enumerate(self.functions) if f in functions]))

    def get_functions(self, indices: List[int]):
        """Get a lisf of functions from their indices

        Args:
            indices: List of indices

        Returns:
            List of functions
        """
        return [self.functions[i] for i in indices]

    def get_other_functions(self, indices: List[int]):
        """Get a lisf of functions not in the indices

        Args:
            indices: List of indices

        Returns:
            List of other functions
        """
        return [
            self.functions[i]
            for i in range(len(self.functions))
            if i not in indices and self.functions[i].package != ""
        ]

    def find_call_chains(
        self, sinks: List[int], max_call_chains: int = 0
    ) -> tuple[List[int], List[List[int]]]:
        """Find call chains to sinks

        Args:
            sinks: indices of sink functions
            max_paths: maximum call chains to keep. default = 0 means no limit

        Returns:
            affected functions indices, call chains
        """
        visited: Dict[int, bool] = {}
        chains: List[List[int]] = []

        def dfs(sink: int) -> List[List[int]]:
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

            all_chains: List[List[int]] = [[]]
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
