# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass


@dataclass(frozen=True)
class Function:
    """A function node

    Attributes:
        parameterTypes: list of parameter types
        templateArguments: list of template arguments
        function: Base name of the function
        name: Qualified name of the function
        package: Package path
        packageIndex: Package index
        language: Language
        type: Function type
        properties: Function properties
    """

    # fields in camelCase as they are in the callgraph json
    parameterTypes: list[str]
    templateArguments: list[str]
    function: str
    name: str
    packageIndex: int
    language: str
    type: str
    properties: list[str]

    def __hash__(self):
        return hash(
            (
                tuple(self.parameterTypes),
                tuple(self.templateArguments),
                self.function,
                self.name,
                self.packageIndex,
                self.language,
                self.type,
                tuple(self.properties),
            )
        )
