# SPDX-FileCopyrightText: 2025-present OpenRefactory, Inc.
# SPDX-FileContributor: Saadman Ahmed (OpenRefactory, Inc.)
#
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass, field
from typing import List, Optional

from analysisReport import AnalysisReport


@dataclass
class Source:
    """Source of a vulnerability or related information

    Attributes:
        name: name of the source
        url: source url
    """

    name: str
    url: str


@dataclass
class Reference:
    """Reference to a related vulnerability from another source

    Attributes:
        source: the source
        id: reference id
    """

    source: Source
    id: str = ""


@dataclass
class Rating:
    """Severity rating of a vulnerability

    Attributes:
        source: source of rating
        score: rating score
        severity: severity
        method: tool/version
        vector: vector string
    """

    source: Source
    score: float
    severity: str
    method: str
    vector: str


@dataclass
class Advisory:
    """External advisory or report related to the vulnerability

    Attributes:
        title: advisory title
        url: advisory url
    """

    title: str
    url: str


@dataclass
class Affects:
    """The affected component using a purl reference

    Attributes:
        ref: the reference in purl format
    """

    ref: str


@dataclass
class CreditIndividual:
    """Individual credited for reporting or identifying the vulnerability

    Attributes:
        name: name of the individual
    """

    name: str


@dataclass
class Credits:
    """List of individuals who should be credited for the vulnerability

    Attributes:
        individuals: List of individuals
    """

    individuals: List[CreditIndividual]


@dataclass
class Vulnerability:
    """A vulnerability entry

    Attributes:
        id: id of the vulnerability
        sources: list of sources
        references: list of references
        ratings: list of ratings
        cwes: list of cwes
        description: description of the vulnerability
        advisories: list of advisories related to the vulnerability
        created: time when the vulnerability was first created
        published: time when the vulnerability was first published
        updated: time when the vulnerability was last updated
        analysis: automated vex analysis report
        affects: list of affected package
        credits: list of credits to individuals
        detail: vulnerability details
        recommendation: recommendations for the vulnerability
    """

    id: str
    sources: List[Source]
    references: List[Reference]
    ratings: List[Rating]
    cwes: List[int]
    description: str
    advisories: List[Advisory]
    created: str
    published: str
    updated: str
    analysis: AnalysisReport
    affects: List[Affects]
    credits: Optional[Credits] = None
    detail: Optional[str] = ""
    recommendation: Optional[str] = ""


@dataclass
class VexDocument:
    """The top-level CycloneDX VEX document structure

    Attributes:
        bomformat: format of the vex document
        specVersion: spec version of the said format
        version: version of the document
        vulnerabilities: list of vulnerabilities
    """

    bomformat: str = "CycloneDX"
    specVersion: str = "1.4"
    version: int = 1
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class PackageToVex:
    """Template object that binds a package with its associated VexDocument

    Attributes:
        package: package in purl format
        vex: vex document
    """

    purl: str
    vex: VexDocument
