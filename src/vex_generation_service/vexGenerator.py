# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
# SPDX-FileContributor: Saadman Ahmed (OpenRefactory, Inc.)
#
# SPDX-License-Identifier: Apache-2.0

import textwrap
from dataclasses import dataclass
from datetime import datetime

from vex_generation_service.analysisReport import (
    AnalysisDetail,
    AnalysisReport,
    AnalysisState,
    ArtifactReachability,
    Explanation,
    Justification,
    Response,
)
from vex_generation_service.function import Function
from vex_generation_service.utils import Package, name
from vex_generation_service.vexDocument import (
    Advisory,
    Affects,
    CreditIndividual,
    Credits,
    PackageToVex,
    Rating,
    Reference,
    Source,
    VexDocument,
    Vulnerability,
)


@dataclass
class VexGenerator:
    """Generates VEX (Vulnerability Exploitability eXchange) data for a given CVE and dependency chain.

    This class orchestrates the process of analyzing reachability and vulnerability information
    across a package dependency chain, and produces a structured VEX representation for each
    relevant package.

    Attributes:
        cve_id: cve id
        vex_helper : partially filled vex document created by rcs
        chain: ordered list of packages in the dependency chain
        root_cause_functions: vulnerable methods found by rcs
        affected: the upstream package that harbors the root cause functions
    """

    def __init__(
        self,
        cve_id: str,
        vex_helper,
        chain: list[Package],
        root_cause_functions: list[str],
        identified_root_cause_functions: list[Function],
        purl: str,
    ):
        """initialize the vex generator"""

        self.cve_id: str = cve_id
        self.vex_helper = vex_helper
        self.chain: list[Package] = chain
        self.root_cause_functions: list[str] = root_cause_functions
        self.identified_root_cause_functions: list[Function] = (
            identified_root_cause_functions
        )
        self.affected: str = purl

    def get_detail(self, pkg_idx: int) -> tuple[str, AnalysisDetail]:
        """Generates detail field for each of the package in chain

        Args:
            package_idx: Index of the package

        Returns:
            Verdict and Analysiss detail
        """
        pkg = self.chain[pkg_idx]
        explanation = self.get_explanation(pkg_idx)
        verdict = explanation.verdict
        return verdict, AnalysisDetail(
            explanations=[explanation],
            root_cause_methods=[f.name for f in self.identified_root_cause_functions],
            reachability_trace=ArtifactReachability(
                reachable=pkg.reachable,
                reachable_paths=pkg.reachable_paths
                if pkg_idx < len(self.chain) - 1
                else [],
                unreachable_paths=pkg.unreachable_paths
                if pkg_idx < len(self.chain) - 1
                else [],
            ),
        )

    def get_explanation(self, package_idx: int) -> Explanation:
        """Generates an explanation object given the reachability trace field of an artifact

        Args:
            package_idx: Index of the package

        Returns:
            The explanation
        """
        package = self.chain[package_idx]
        verdict = "update" if package.reachable is True else "will not fix"
        author = "VGS"
        message = self.get_message(package_idx)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return Explanation(
            verdict=verdict, message=message, author=author, timestamp=timestamp
        )

    def get_message(self, pkg_idx: int) -> str:
        """Populate an intuitive message based on the reachable and unreachable paths

        Args:
            pkg_idx: Index of the package

        Returns:
            The message
        """

        pkg = self.chain[pkg_idx]
        if pkg_idx == len(self.chain) - 1:
            return f"{name(pkg.purl)} harbors the vulnerability {self.cve_id}.\n"

        is_reachable = pkg.reachable

        affected_pkg = self.chain[-1]
        affected_functions = self.identified_root_cause_functions
        affected_function_names = [f.name for f in affected_functions]
        affected_function_list = "\n - ".join(affected_function_names)

        msg = f"{self.cve_id}, reported in {name(affected_pkg.purl)}, {'directly impacts' if is_reachable else 'does not impact'} {name(pkg.purl)}.\n"
        msg += f"\nThe dependency chain from {name(pkg.purl)} to {name(affected_pkg.purl)} is shown here (──> means depends on):\n"
        msg += (
            "\n"
            + " ──> ".join(
                [name(self.chain[i].purl) for i in range(pkg_idx, len(self.chain))]
            )
            + "\n"
        )
        if len(self.root_cause_functions) < 1:
            msg += "\nNo root cause functions were provided in the input file.\n"
        elif len(affected_function_names) < 1:
            msg += (
                "\nCould not identify root cause functions in the affected callgraph.\n"
            )
        else:
            msg += f"\nThe root cause functions in {name(affected_pkg.purl)} are:\n"
            msg += f"\n - {affected_function_list}\n"

        # TODO:
        # Once we get the root cause explanations, we will be able to show rationale
        # behind each root cause found using llm summary
        # msg += "\nWe identified the root causes in the following way:\n"
        # msg += f"{self.root_cause_rationale}"

        if is_reachable and len(pkg.reachable_paths) > 0:
            # Case 1: The bug is reachable from this downstream package
            call_chain = pkg.reachable_paths[0]
            reachable_path = [call.callerName for call in call_chain] + [
                call_chain[-1].calleeName
            ]

            formatted_path = "\n└─>".join(reachable_path)
            msg += f"\nHere is a call chain that shows how a root cause function is called from {name(pkg.purl)}\n"
            msg += f"\n{formatted_path}\n"
            msg += f"\nThere are {len(pkg.reachable_paths) - 1} other traces in which at least one root cause function is called from {name(pkg.purl)}\n"

        else:
            # Case 2: The bug is unreachable from the first downstream package
            if pkg_idx == len(self.chain) - 2 and len(pkg.unreachable_paths) > 0:
                call_chain = pkg.unreachable_paths[0]
                unreachable_path = [call.callerName for call in call_chain] + [
                    call_chain[-1].calleeName
                ]

                formatted_path = "\n└─>".join(unreachable_path)
                msg += f"\nThe first downstream package, {name(pkg.purl)}, has {len(pkg.unreachable_paths)} calls to different methods in {name(affected_pkg.purl)}, but none of them calls any of the root cause functions. Here is an example call chain:\n"
                msg += f"\n{formatted_path}\n"
                msg += f"\nSince the root cause functions are not reachable at {name(pkg.purl)}, the packages further downstream are not affected.\n"
                msg += f"\n{name(pkg.purl)} does not need an update\n"
            else:
                # Case 3: The bug is unreachable from other downstream package
                for i in range(len(self.chain) - 2, pkg_idx - 1, -1):
                    down_pkg = self.chain[i]
                    if down_pkg.reachable and len(down_pkg.reachable_paths) > 0:
                        call_chain = down_pkg.reachable_paths[0]
                        reachable_path = [call.callerName for call in call_chain] + [
                            call_chain[-1].calleeName
                        ]
                        formatted_path = "\n└─>".join(reachable_path)
                        msg += f"\nThe {'first' if i == len(self.chain) - 2 else 'next'} downstream package, {name(down_pkg.purl)}, calls at least one of the vulnerable functions. Here is an example call chain:\n"
                        msg += f"\n{formatted_path}\n"
                    else:
                        if len(down_pkg.unreachable_paths) > 0:
                            call_chain = down_pkg.unreachable_paths[0]
                            unreachable_path = [
                                call.callerName for call in call_chain
                            ] + [call_chain[-1].calleeName]

                            formatted_path = "\n└─>".join(unreachable_path)
                            msg += f"\nThe next downstream package, {name(down_pkg.purl)}, has {len(down_pkg.unreachable_paths)} calls to different methods in {name(self.chain[i + 1].purl)}, but none of them calls any of the root cause functions. An example is given here.\n"
                            msg += f"\n{formatted_path}\n"
                            msg += f"\nSince the root cause functions are not reachable at {name(down_pkg.purl)}, the packages further downstream are not affected.\n"

                        msg += f"\n{name(down_pkg.purl)} does not need an update\n"

        return textwrap.dedent(msg)

    def get_analysis_report(self, pkg_idx: int) -> AnalysisReport:
        """Populate "analysis" field for a given package that will be inside the vex

        Args:
            package_idx: Index of the package in a chain
        Return:
            the AnalysisReport object for that particular package or artifact
        """

        verdict, detail = self.get_detail(pkg_idx)
        state = (
            AnalysisState.AFFECTED if verdict == "update" else AnalysisState.UNAFFECTED
        )
        justification = (
            Justification.FUNCTION_REACHABLE
            if verdict == "update"
            else Justification.NOT_FUNCTION_REACHABLE
        )
        response = Response.UPDATE if verdict == "update" else Response.WILL_NOT_FIX
        return AnalysisReport(
            state=state, justification=justification, response=response, detail=detail
        )

    def populate_list_of_vex(self) -> list[PackageToVex]:
        """Generate the full VEX document based on analysis reports and helper metadata,
        and safely append it to a JSON array in the specified file.

        Returns:
            a list of PackageToVex objects
        """
        meta = self.vex_helper
        sources = [Source(**src["source"]) for src in meta.get("sources", [])]
        references = (
            [Reference(**ref) for ref in meta.get("references", [])]
            if "references" in meta
            else []
        )
        ratings = [Rating(**r) for r in meta.get("ratings", [])]
        advisories = [Advisory(**adv) for adv in meta.get("advisories", [])]
        cwes = meta.get("cwes", [])
        description = meta.get("description", "")
        detail = meta.get("detail", "")
        recommendation = meta.get("recommendation", "")
        created = meta.get("created", "")
        published = meta.get("published", "")
        updated = meta.get("updated", "")
        credits_data = meta.get("credits", {}).get("individuals", [])
        credits_obj = (
            Credits([CreditIndividual(**c) for c in credits_data])
            if credits_data
            else None
        )
        package_to_vex: list[PackageToVex] = []

        for pkg_idx, pkg in enumerate(self.chain):
            analysis = self.get_analysis_report(pkg_idx)
            vuln = Vulnerability(
                id=self.cve_id,
                sources=sources,
                references=references,
                ratings=ratings,
                cwes=cwes,
                description=description,
                detail=detail,
                recommendation=recommendation,
                advisories=advisories,
                created=created,
                published=published,
                updated=updated,
                credits=credits_obj,
                analysis=analysis,
                affects=[Affects(ref=f"{self.affected}")],
            )
            vex = VexDocument(vulnerabilities=[vuln])
            package_to_vex.append(PackageToVex(purl=pkg.purl, vex=vex))
        return package_to_vex
