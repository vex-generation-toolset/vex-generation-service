# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import re
from dataclasses import dataclass
from typing import List


@dataclass
class Function:
    """A function node

    Attributes:
        parameterTypes: List of parameter types
        templateArguments: List of template arguments
        function: Base name of the function
        name: Qualified name of the function
        package: Package path
        packageIndex: Package index
        language: Language
        type: Function type
        properties: Function properties
        visited: Did we visit this function node when traversing the graph?
    """

    # fields in camelCase as they are in the callgraph json
    parameterTypes: List
    templateArguments: List
    function: str
    name: str
    package: str
    packageIndex: int
    language: str
    type: str
    properties: List

    visited: bool = False

    def __eq__(self, other) -> bool:
        """Custom function similarity check

        Args:
            other (str | Function): Qualified function name in canonical format or Function object

        Returns:
            True if the functions match, False otherwise
        """

        def string_match(other: str) -> bool:
            """The matching algorithm to use when other is a string

            Args:
                other: Qualified function name in canonical format

            Returns:
                True if the functions match, False otherwise
            """
            match self.language:
                # build a dynamic pattern using regular expression in the canonical format from the functino object
                case "java":
                    escaped_package = '' if self.package == '' else re.escape(self.package + '.')
                    escaped_parameterTypes = ', *'.join([re.escape(p) for p in self.parameterTypes])
                    pattern = rf"{escaped_package}{re.escape(self.type)}[.#]{self.function}\({escaped_parameterTypes}\)"

                case _:
                    return False

            # search the pattern in the other function name in canonical format
            # if both functions are in the canonical format and same, they are supposed to match
            if re.search(pattern, other):
                return True

            return False

        def function_match(other: Function) -> bool:
            """The matching algorithm to use when other is a Function

            Args:
                other: The other function to match

            Returns:
                True if the functions match, False otherwise
            """
            match_found = True
            match_found &= self.language == other.language
            match_found &= self.function == other.function
            self_pkg_type = (
                f"{self.type}" if self.package == "" else f"{self.package}.{self.type}"
            )
            other_pkg_type = (
                f"{other.type}"
                if other.package == ""
                else f"{other.package}.{other.type}"
            )
            match_found &= self_pkg_type == other_pkg_type

            match_found &= self.parameterTypes == other.parameterTypes
            # if match_found:
            #     print(f"Matched: {self.name} == {other.name}")
            return match_found

        match other:
            case str():
                return string_match(other)
            case Function():
                return function_match(other)
            case _:
                return False
