# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
import shutil
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import List

from function import Function
from graph import Call
from utils import Package, load_graph
from vexDocument import PackageToVex
from vexGenerator import VexGenerator


class Analysis:
    def __init__(self, input: str):
        """initialize the analysis

        Args:
            input: input file path
            output: output file path
        """
        self.cve_id: str = ""
        self.purl: str = ""
        self.root_cause_functions: List[str] = []
        self.chains: List[List[Package]] = []
        self.vex = {}

        self.setup()
        self.load(input)

    def setup(self):
        """setup the environment for analysis"""
        self.download_path = Path("/tmp/callgraphs/").absolute()
        if self.download_path.exists():
            shutil.rmtree(self.download_path)
        self.download_path.mkdir(exist_ok=True)

    def load(self, input: str | Path):
        """Load the input file

        Args:
            input: path to input file
        """

        def get_package(pkg) -> Package:
            """Get package from josn object
            Downloads the callgraph from the url and stores
            the download path as the path to callgraph inside package

            Args:
                pkg : json object in the format: {"purl": "pkg:type/name@version", "callgraph": "https://example.com/some_cg.json"}

            Returns:
                Package
            """

            callgraph_url = pkg.get("callgraph")
            safe_purl = pkg.get('purl').replace(':', '_').replace('/', '_').replace('@', '_')
            filename = f"{self.download_path.as_posix()}/{safe_purl}.json"
            subprocess.run(
                ["curl", "-o", filename, callgraph_url],
                # f"curl -o '{filename}' '{callgraph_url}'",
                capture_output=True,
                timeout=20,
            )
            return Package(**{**pkg, "callgraph": filename})

        with open(input, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.cve_id = data.get("cve_id")
        self.purl = data.get("purl")
        self.root_cause_functions = data.get("root_cause_functions")
        chains = data.get("chains")
        self.chains = [[get_package(pkg) for pkg in chain] for chain in chains]
        self.vex = data.get("vex")

    def analyze(self, chain: List[Package]):
        """Run a reachability analysis on a dependency chain

        Args:
            chain: List of packages in a dependency chain maintaining dependency order
        """

        def merge_paths(
            paths_a: List[List[Function]], paths_b: List[List[Function]]
        ) -> List[List[Function]]:
            """Merge paths from one callgraph with paths of another callgraph

            Args:
                paths_a: paths of callgraph A
                paths_b: paths of callgraph B

            Returns:
                Merged paths
            """
            merged_paths: List[List[Function]] = []
            for path_a in paths_a:
                last_func = path_a[-1]

                for path_b in paths_b:
                    if last_func in path_b:
                        func_idx = path_b.index(last_func)
                        merged_paths.append(path_a[:-1] + path_b[func_idx:])

            return merged_paths

        def merge_call_chains(
            call_chains_a: List[List[Call]], call_chains_b: List[List[Call]]
        ) -> List[List[Call]]:
            """Merge call chains from one callgraph with call chains of another callgraph

            Args:
                call_chain_a: call chains of callgraph A
                call_chain_b: call chains of callgraph B

            Returns:
                Merged call chains
            """
            merged_call_chains: List[List[Call]] = []
            for call_chain_a in call_chains_a:
                if len(call_chain_a) < 1:
                    continue
                last_call_a = call_chain_a[-1]

                add_call_chain_a_once = False
                for call_chain_b in call_chains_b:
                    if len(call_chain_b) < 1:
                        add_call_chain_a_once = True
                        continue
                    first_call_b = call_chain_b[0]
                    if last_call_a.calleeName == first_call_b.callerName:
                        merged_call_chains.append(call_chain_a + call_chain_b)

                # Here, we handle a specific scenario:
                # assume package b is a library package and the vulnerable functions
                # are not being called by any other functions in the same package
                # Now, we have call_chains_b = []
                # But assume, package a is using the vulnerable functions from package b
                # we now have a call to the vulnerable function in package a
                # this call has a call chain, i.e., call_chain_a
                # we need to add this call chain to the merged call chain
                if add_call_chain_a_once:
                    merged_call_chains.append(call_chain_a)

            return merged_call_chains

        def get_unique_funcs(indices: List[int]) -> List[int]:
            """Get unique function indices from a list of paths

            Args:
                paths: List of paths

            Returns:
                Unique list of function indices
            """
            return list(set(indices))

        merged_paths: List[List[Function]] = []

        affected = load_graph(chain[-1].callgraph)
        sinks = affected.find_sinks(self.root_cause_functions)
        affected_paths = affected.find_paths(sinks)
        unique_function_indices = get_unique_funcs(
            [func for path in affected_paths for func in path]
        )

        unique_funcs_in_affected_paths = affected.get_functions(unique_function_indices)
        unique_funcs_not_in_affected_path = affected.get_other_functions(
            unique_function_indices
        )

        chain[-1].reachable = True
        merged_paths = [
            affected.get_functions(path_indices) for path_indices in affected_paths
        ]
        merged_call_chains = [
            affected.find_call_chain(affected_path) for affected_path in affected_paths
        ]

        chain[-1].reachable_paths = merged_call_chains

        for pkg in chain[-2::-1]:
            candidate = load_graph(pkg.callgraph)
            sinks = candidate.find_sinks(unique_funcs_in_affected_paths)
            affected_paths = candidate.find_paths(sinks)
            affected_call_chains = [
                candidate.find_call_chain(affected_path)
                for affected_path in affected_paths
            ]
            unique_function_indices = get_unique_funcs(
                [func for path in affected_paths for func in path]
            )

            if len(unique_function_indices) == 0:
                pkg.reachable = False
                sinks = candidate.find_sinks(unique_funcs_not_in_affected_path)
                unreachable_paths = candidate.find_paths(sinks, 5)
                unreachable_call_chains = [
                    candidate.find_call_chain(unreachable_path)
                    for unreachable_path in unreachable_paths
                ]
                pkg.unreachable_paths = unreachable_call_chains
                break

            unique_funcs_in_affected_paths = candidate.get_functions(
                unique_function_indices
            )
            unique_funcs_not_in_affected_path = affected.get_other_functions(
                unique_function_indices
            )
            pkg.reachable = True
            affected_function_paths = [
                candidate.get_functions(path_indices) for path_indices in affected_paths
            ]
            merged_paths = merge_paths(affected_function_paths, merged_paths)
            merged_call_chains = merge_call_chains(
                affected_call_chains, merged_call_chains
            )
            pkg.reachable_paths = merged_call_chains

    def run(self):
        """Run reachability analysis"""
        for chain in self.chains:
            self.analyze(chain)

    def export_vex(self, output: str | Path):
        """Export the analysis vex reports

        Args:
            output: path to output file
        """
        vex_chains: List[List[PackageToVex]] = []
        for chain in self.chains:
            generator = VexGenerator(
                cve_id=self.cve_id,
                vex_helper=self.vex,
                chain=chain,
                root_cause_functions=self.root_cause_functions,
                purl=self.purl,
            )
            vex_chain = generator.populate_list_of_vex()
            vex_chains.append(vex_chain)

        for vex_chain in vex_chains:
            for vex in vex_chain:
                print(
                    vex.vex.vulnerabilities[0].analysis.detail.explanations[0].message
                )
                print("=" * 120)
        json.dump(
            [[asdict(vex) for vex in vex_chain] for vex_chain in vex_chains],
            open(output, "w"),
            indent=2,
        )
