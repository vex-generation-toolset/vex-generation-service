# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
# SPDX-FileContributor: Saadman Ahmed (OpenRefactory, Inc.)
#
# SPDX-License-Identifier: Apache-2.0

import argparse

from src.vex_generation_service.analysis import Analysis
from typing import Sequence

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="""Analyze function callgraphs and root cause functions
        Find out all paths that lead to the root cause"""
    )
    parser.add_argument("--input", required=True, help="Path to input JSON file")
    parser.add_argument("--output", required=True, help="Path to output JSON file")
    args = parser.parse_args(argv)

    analysis = Analysis(input=args.input)
    analysis.run()
    analysis.export_vex(output=args.output)
    return 0
