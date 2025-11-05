# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

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
            self.functions[i] for i in range(len(self.functions)) if i not in indices
        ]

    def get_calls(self, indices: List[int]) -> List[Call]:
        """Get a list of calls from their indices

        Args:
            indices: List of indices

        Returns:
            List of calls
        """
        return [self.calls[i] for i in indices]

    def find_call(self, caller: int, callee: int) -> Call | None:
        """Find a call given a caller and a callee

        Args:
            caller: Caller index
            callee: Callee index

        Returns:
            The first call by the caller to callee
        """
        calls = [
            call
            for call in self.calls
            if call.caller == caller and call.callee == callee
        ]
        if len(calls) > 0:
            return calls[0]
        else:
            return None

    def find_call_chain(self, path: List[int]) -> List[Call]:
        """Find the call chain given a path

        Args:
            path: The list of function indices in order of traversal

        Returns:
            An ordered list of calls as a chain
        """
        call_chain: List[Call] = []
        for i in range(len(path) - 1):
            call = self.find_call(path[i], path[i + 1])
            if call:
                call_chain.append(call)

        return call_chain

    def find_paths(self, sinks: List[int]) -> List[List[int]]:
        """Find all paths to the sinks recursively

        Args:
            sinks: List of function indices

        Returns:
            List of paths
        """
        paths: List[List[int]] = []
        for sink in sinks:
            if self.functions[sink].visited:
                continue
            self.functions[sink].visited = True
            result = [call for call in self.calls if call.callee == sink]
            callers = [call.caller for call in result]
            if len(callers) == 0:
                paths.append([sink])
                self.functions[sink].visited = False
                continue
            paths_to_callers = self.find_paths(callers)
            for path in paths_to_callers:
                paths.append(path + [sink])
            self.functions[sink].visited = False
        return paths
