<!--
SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.

SPDX-License-Identifier: Apache-2.0
-->

# VEX Generation Service

VGS, or VEX Generation Service is a part of Project Clean Beach. This service generates a VEX (Vulnerability EXchange format) file based on call graphs and root cause given by RCS.

## Getting Started

- Create an `input.json` file in the format described in [`examples/input.json`](./examples/input.json) file. And run the script in the following way:

    ```bash
    python3 main.py --input input.json --output output.json
    ```

## Contributions

For developing a new feature, create an issue related to that feature or enhancement. Then create a branch from `master`/`main` called `dev-X` where `X` is the issue number. Changes should be made to that branch. Upon finalization, the commits of the feature branch should be rebased against `master`/`main` and then squashed into a single one. Then that commit will be cherry-picked to the main branch. The old branch (`dev-XXX`) will be deleted.
