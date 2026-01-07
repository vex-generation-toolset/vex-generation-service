# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
from dataclasses import dataclass, field
from functools import lru_cache

from vex_generation_service.function import Function


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


def name(purl: str) -> str:
    """A utility function to return short names from purl

    Args:
        purl: package url

    Returns:
        shortened name
    """
    return purl.split("/")[-1]


def is_variadic(parameter_types: list[str]) -> bool:
    """Check if the function is variadic

    Returns:
        True if the function is variadic, False otherwise
    """
    return parameter_types[-1].endswith("...") if len(parameter_types) > 0 else False


def get_param_types(function: str | Function) -> list[str]:
    """Get parameter types from function or function name

    Args:
        function: function name

    Returns:
        parameter types
    """
    match function:
        case Function():
            return function.parameterTypes
        case str():
            return (
                function[function.find("(") + 1 : function.find(")")].split(",")
                if function.find("(") != -1 and function.find(")") != -1
                else []
            )


def is_candidate(function: str, reference: str) -> bool:
    """Is a function a candidate of the reference function

    Args:
        function: given function name
        reference: reference function name

    Returns:
        Returns True if the given function is a candidate of the reference function
    """
    function = function.strip(" ").replace("#", ".")
    reference = reference.strip(" ").replace("#", ".")
    candidate_name = function[: function.find("(")]
    return reference.startswith(candidate_name)


@lru_cache(maxsize=1000, typed=True)
def score_candidate(candidate: Function | str, reference: str) -> int:
    """Score a candidate based on how many parameters match

    Args:
        candidate: Candidate function index
        param_types: list of parameter types
        is_variadic: Is the function variadic

    Returns:
        Score of the candidate
    """
    candidate_param_types = get_param_types(candidate)
    candidate_is_variadic = is_variadic(candidate_param_types)
    param_types = get_param_types(reference)
    variadic = is_variadic(param_types)

    if not candidate_is_variadic and len(candidate_param_types) != len(param_types):
        return -1

    score = 0
    if candidate_is_variadic and variadic:
        score += 2
    elif candidate_is_variadic and not variadic:
        score += 1
    elif not candidate_is_variadic and variadic:
        score -= 1

    for i, param_type in enumerate(param_types):
        if i < len(candidate_param_types):
            candidate_param_type = candidate_param_types[i]
            if candidate_param_type == param_type:
                score += 2
            if param_type in candidate_param_type:
                score += 1
            if candidate_param_type.startswith(param_type):
                score += 1
            if candidate_param_type.endswith(param_type):
                score += 1
            if candidate_param_type.startswith(param_type[: param_type.find("<")]):
                score += 1
            if candidate_param_type.startswith(param_type[: param_type.find("...")]):
                score += 1
            if candidate_param_type == "Object":
                score += 1
    return score


def merge_call_chains(
    chains_a: list[list[Call]],
    chains_b: list[list[Call]],
) -> list[list[Call]]:
    """Merge call chains from one callgraph with call chains of another callgraph

    Args:
        chains_a: call chains of callgraph A
        chains_b: call chains of callgraph B

    Returns:
        Merged call chains
    """
    merged_chains: list[list[Call]] = []

    for chain_a in chains_a:
        if len(chain_a) < 1:
            continue

        last_call_a = chain_a[-1]

        add_chain_a_once = len(chains_b) < 1
        for chain_b in chains_b:
            # Here, we handle 2 specific scenarios:
            # 1. assume call_chain_b = []
            # this can happen if the affected functions are not being called inside
            # package b by any other function. in that case there will be no call
            # chain to the affected functions in graph b
            # 2. assume package a directly calls the callee function of the last call of call_chain_b
            # in that case, last_call_a.calleeName is a candidate of last_call_b.calleeName
            #
            # In both of these cases, call_chain_a should be added to the merged_call_chains once
            if len(chain_b) < 1:
                add_chain_a_once = True
                break

            last_call_b = chain_b[-1]
            if is_candidate(last_call_a.calleeName, last_call_b.calleeName):
                candidate_score = score_candidate(
                    last_call_a.calleeName, last_call_b.calleeName
                )
                if candidate_score >= 0:
                    add_chain_a_once = True
                    continue

            best_score = -1
            best_candidate = None
            for i, call in enumerate(chain_b):
                if last_call_a.calleeName == call.callerName:
                    best_candidate = i
                    break

                if is_candidate(last_call_a.calleeName, call.callerName):
                    candidate_score = score_candidate(
                        last_call_a.calleeName, call.callerName
                    )
                    if candidate_score > best_score:
                        best_candidate = i
                        best_score = candidate_score

            if best_candidate is not None:
                merged_chains.append(chain_a + chain_b[best_candidate:])
                break

        if add_chain_a_once:
            merged_chains.append(chain_a)

    return merged_chains
