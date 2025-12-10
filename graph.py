# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from function import Function


@dataclass(frozen=True)
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


@dataclass(frozen=True)
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

        def score_candidate(
            candidate: Function, param_types: list[str], is_variadic: bool
        ) -> int:
            """Score a candidate based on how many parameters match

            Args:
                candidate: Candidate function index
                param_types: list of parameter types
                is_variadic: Is the function variadic

            Returns:
                Score of the candidate
            """
            candidate_param_types = candidate.parameterTypes
            if not candidate.is_variadic() and len(candidate_param_types) != len(
                param_types
            ):
                return -1

            score = 0
            if candidate.is_variadic() and is_variadic:
                score += 2
            elif candidate.is_variadic() and not is_variadic:
                score += 1
            elif not candidate.is_variadic() and is_variadic:
                score -= 1

            for i, param_type in enumerate(param_types):
                if i < len(candidate_param_types):
                    candidate_param_type = candidate_param_types[i]
                    if candidate_param_type == param_type:
                        score += 2
                    if candidate_param_type.startswith(param_type):
                        score += 1
                    if candidate_param_type.endswith(param_type):
                        score += 1
                    # allow "Object" to match any type
                    if candidate_param_type == "Object":
                        score += 1
                    # allow type erasure
                    if candidate_param_type.startswith(
                        param_type[: param_type.find("<")]
                    ):
                        score += 1
                    # handle variadic functions
                    if candidate_param_type.startswith(
                        param_type[: param_type.find("...")]
                    ):
                        score += 1
            return score

        match function:
            case str():
                function = function.strip(" ")
            case Function():
                function = function.name.strip(" ")

        if function in self.best_candidate:
            return self.best_candidate[function]

        name = function[: function.find("(")]
        param_types = (
            function[function.find("(") + 1 : function.find(")")].split(",")
            if function.find("(") != -1 and function.find(")") != -1
            else []
        )
        is_variadic = param_types[-1].endswith("...") if len(param_types) > 0 else False
        candidates: list[int] = [
            i for i, f in enumerate(self.functions) if f.name.startswith(name)
        ]

        best_score = -1
        best_candidate = None
        for c in candidates:
            candidate = self.functions[c]
            if candidate.name == function:
                self.best_candidate[function] = c
                return c
            score = score_candidate(candidate, param_types, is_variadic)
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
