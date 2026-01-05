# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import json
import subprocess
from pathlib import Path

from function import Function
from graph import load_graph
from utils import (
    CustomEncoder,
    Package,
    merge_call_chains,
    name,
)
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
        self.root_cause_functions: list[str]
        self.identified_root_cause_functions: list[Function]
        self.chains: list[list[Package]]
        self.vex = {}

        self.setup()
        self.load(input)

    def setup(self):
        """setup the environment for analysis"""
        self.download_path = Path("/tmp/callgraphs/").absolute()
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

            purl = pkg.get("purl")
            callgraph_url = pkg.get("callgraph")
            filename = f"{self.download_path.as_posix()}/{
                purl.replace(':', '_').replace('/', '_').replace('@', '_')
            }.json"
            print(
                f"[+] downloading callgraph for {name(purl)} from {callgraph_url} to {filename}"
            )
            subprocess.run(
                ["curl", "-o", filename, "-C", "-", callgraph_url],
                capture_output=True,
                timeout=20,
            )
            return Package(**{**pkg, "callgraph": filename})

        with open(input, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.cve_id = data.get("cve_id", "")
        self.purl = data.get("purl", "")
        self.root_cause_functions = data.get("root_cause_functions", [])
        chains = data.get("chains", [[]])
        self.chains = [[get_package(pkg) for pkg in chain] for chain in chains]
        self.vex = data.get("vex")

    def analyze(self, chain: list[Package]):
        """Run a reachability analysis on a dependency chain

        Args:
            chain: list of packages in a dependency chain maintaining dependency order
        """

        pkg = chain[-1]
        print(f"[+] {name(pkg.purl)} is affected by {self.cve_id}")
        print(f"[+] loading callgraph for {name(pkg.purl)} from {pkg.callgraph}")
        affected = load_graph(pkg.callgraph)
        print(f"[+] found {len(affected.functions)} functions in the callgraph")
        print(f"[+] found {len(affected.calls)} function calls in the callgraph")
        print("[+] identifying the root cause functions in the callgraph")
        sinks = affected.find_sinks(self.root_cause_functions)
        self.identified_root_cause_functions = affected.get_functions(sinks)
        print(f"[+] identified {len(sinks)} sinks")
        print("[+] finding call chains to the identified sinks")
        unique_function_indices, affected_call_chains = affected.find_call_chains(sinks)
        print(f"[+] found {len(affected_call_chains)} affected call chains")
        print(
            f"[+] found {len(unique_function_indices)} unique functions in the affected call chains"
        )

        unique_reachable_functions = affected.get_functions(unique_function_indices)
        unique_unreachable_functions = affected.get_other_functions(
            unique_function_indices
        )

        chain[-1].reachable = True
        merged_call_chains = [
            [affected.calls[call] for call in call_chain]
            for call_chain in affected_call_chains
            if len(call_chain) > 0
        ]
        chain[-1].reachable_paths = merged_call_chains

        for pkg in chain[-2::-1]:
            print(f"[+] analyzing {name(pkg.purl)}")
            print(f"[+] loading callgraph for {name(pkg.purl)} from {pkg.callgraph}")
            candidate = load_graph(pkg.callgraph)
            print(f"[+] found {len(candidate.functions)} functions in the callgraph")
            print(f"[+] found {len(candidate.calls)} function calls in the callgraph")
            print("[+] identifying affected functions in the callgraph")
            sinks = candidate.find_sinks(unique_reachable_functions)
            print(f"[+] identified {len(sinks)} sinks")
            print("[+] finding call chains to the identified sinks")
            unique_function_indices, _affected_call_chains = candidate.find_call_chains(
                sinks
            )
            affected_call_chains = [
                [candidate.calls[call] for call in call_chain]
                for call_chain in _affected_call_chains
                if len(call_chain) > 0
            ]
            print(f"[+] found {len(affected_call_chains)} affected call chains")
            print(
                f"[+] found {len(unique_function_indices)} unique function in the affected call chains"
            )

            if len(unique_function_indices) == 0:
                pkg.reachable = False
                print("[+] did not find any call chain to the identified sinks")
                print(f"[+] {name(pkg.purl)} is not affected by {self.cve_id}")
                print("[+] identifying unreachable functions in the callgraph")
                sinks = candidate.find_sinks(unique_unreachable_functions)
                print(
                    f"[+] identified {len(sinks)} sinks from {len(unique_unreachable_functions)} unique functions"
                )
                print("[+] finding call chains to the identified sinks")
                _, unreachable_call_chains = candidate.find_call_chains(sinks)
                print(
                    f"[+] found {len(unreachable_call_chains)} call chains to the sinks"
                )
                pkg.unreachable_paths = [
                    [candidate.calls[call] for call in call_chain]
                    for call_chain in unreachable_call_chains
                    if len(call_chain) > 0
                ]
                break

            unique_reachable_functions = candidate.get_functions(
                unique_function_indices
            )
            unique_unreachable_functions = candidate.get_other_functions(
                unique_function_indices
            )
            pkg.reachable = True

            merged_call_chains = merge_call_chains(
                affected_call_chains, merged_call_chains
            )

            print(f"[+] {name(pkg.purl)} is affected by {self.cve_id}")
            pkg.reachable_paths = merged_call_chains

    def run(self):
        """Run reachability analysis"""
        for i, chain in enumerate(self.chains):
            self.analyze(chain)
            print(f"[+] analysis complete for chain index {i}")
        load_graph.cache_clear()

    def export_vex(self, output: str | Path):
        """Export the analysis vex reports

        Args:
            output: path to output file
        """
        vex_chains: list[list[PackageToVex]] = []
        print("[+] populating VEX document")
        for chain in self.chains:
            generator = VexGenerator(
                cve_id=self.cve_id,
                vex_helper=self.vex,
                chain=chain,
                root_cause_functions=self.root_cause_functions,
                identified_root_cause_functions=self.identified_root_cause_functions,
                purl=self.purl,
            )
            vex_chain = generator.populate_list_of_vex()
            vex_chains.append(vex_chain)

        for vex_chain in vex_chains:
            print()
            for vex in vex_chain:
                print(
                    vex.vex.vulnerabilities[0].analysis.detail.explanations[0].message
                )
                print("=" * 120)
        print("[+] writing VEX document")
        json.dump(
            [[vex for vex in vex_chain] for vex_chain in vex_chains],
            open(output, "w"),
            cls=CustomEncoder,
            indent=2,
        )
        print("[+] finished writing VEX document")
