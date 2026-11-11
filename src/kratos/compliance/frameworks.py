"""The frameworks Kratos maps its checks to (E.2 §3.2): ids, and Kratos's own words.

- ISO/IEC 27001:2022 Annex A -- the 93 control ids in four themes (5.x organisational,
  6.x people, 7.x physical, 8.x technological). ISO's text is copyrighted: only the ids
  ship. Each description here is Kratos's own one line about the subject, and for
  controls Kratos can't see, what a person would show instead.
- NIS2 -- Article 21(2) points (a)-(j) of Directive (EU) 2022/2555, and the sections
  of the Annex to Commission Implementing Regulation (EU) 2024/2690. EU legal text may
  be reused, but Kratos still ships ids and its own short wording. The regulation binds
  certain digital-infrastructure and digital-provider entities; for everyone else it is
  used as guidance (ENISA's June 2025 technical implementation guidance is cited, not
  copied).

The mapping from Kratos checks to these ids is Kratos's own work, advisory ("Kratos's
checks that give evidence for this control"), never a claim of certification.
"""
from __future__ import annotations

from dataclasses import dataclass

FRAMEWORKS: tuple[str, ...] = ("cis", "iso27001", "nis2")
FRAMEWORK_NAMES: dict[str, str] = {
    "cis": "CIS Benchmark (via ComplianceAsCode control ids)",
    "iso27001": "ISO/IEC 27001:2022 Annex A",
    "nis2": "NIS2 (Directive (EU) 2022/2555 Art. 21(2); Implementing Regulation (EU) 2024/2690 Annex)",
}
NOT_A_CERTIFICATION = ("Evidence from Kratos's checks, not a certification, an audit or legal advice. A pass "
                       "means Kratos read the proof on this machine; it says nothing about what Kratos can't see.")
NIS2_SCOPE_NOTE = ("Implementing Regulation (EU) 2024/2690 binds certain digital-infrastructure and digital-"
                   "provider entities; for other organisations it is used here as guidance. See also ENISA's NIS2 "
                   "Technical Implementation Guidance (June 2025).")


@dataclass(frozen=True)
class Control:
    framework: str
    id: str
    theme: str
    text: str                     # Kratos's own one line
    person: str = ""              # what a person supplies when Kratos can't see it


def _iso(cid: str, text: str, person: str = "") -> Control:
    theme = {"5": "organisational", "6": "people", "7": "physical", "8": "technological"}[cid.split(".")[0]]
    return Control("iso27001", cid, theme, text, person)


_DOC = "a written, approved document and evidence it is followed"
_REC = "records showing it is done (e.g. tickets, sign-offs, review notes)"

ISO_CONTROLS: tuple[Control, ...] = (
    _iso("5.1", "Information-security policies exist and are approved.", _DOC),
    _iso("5.2", "Who does what in information security is assigned.", "a list of roles and the people in them"),
    _iso("5.3", "Duties that conflict are kept apart.", "a description of which duties are separated"),
    _iso("5.4", "Management makes people follow the security rules.", _REC),
    _iso("5.5", "Contacts with authorities are kept.", "the contact list and when it was last checked"),
    _iso("5.6", "Contacts with security interest groups are kept.", "memberships and contact points"),
    _iso("5.7", "Threat information is gathered and used.", "the feeds used and how alerts are handled"),
    _iso("5.8", "Security is part of project management.", _REC),
    _iso("5.9", "An inventory of information and assets is kept, with owners.",
         "the asset inventory (Kratos's own machine list and asset records help, but don't cover everything)"),
    _iso("5.10", "Rules for acceptable use of information and assets.", _DOC),
    _iso("5.11", "Assets are returned when people leave.", _REC),
    _iso("5.12", "Information is classified.", "the classification scheme and labels in use"),
    _iso("5.13", "Information is labelled by its classification.", "examples of labelling"),
    _iso("5.14", "Information transfer is covered by rules or agreements.", _DOC),
    _iso("5.15", "Access-control rules are set and followed.", _DOC),
    _iso("5.16", "Identities are managed over their whole life.", _REC),
    _iso("5.17", "Authentication secrets are handed out and managed properly.", _DOC),
    _iso("5.18", "Access rights are granted, reviewed and removed.", "access reviews and their outcome"),
    _iso("5.19", "Supplier risks are managed.", _DOC),
    _iso("5.20", "Security is part of supplier agreements.", "the contracts' security clauses"),
    _iso("5.21", "ICT supply-chain risks are managed.", _DOC),
    _iso("5.22", "Supplier services are monitored and changes reviewed.", _REC),
    _iso("5.23", "Security of cloud services is managed.", _DOC),
    _iso("5.24", "Incident management is planned and prepared.", "the incident plan and who is on call"),
    _iso("5.25", "Security events are assessed and classified.", _REC),
    _iso("5.26", "Incidents are responded to by a set procedure.", "the procedure and past incident records"),
    _iso("5.27", "Lessons are learned from incidents.", "post-incident reviews"),
    _iso("5.28", "Evidence is collected and preserved.",
         "the evidence procedure (Kratos's signed incident exports can be part of it)"),
    _iso("5.29", "Security is kept during disruption.", _DOC),
    _iso("5.30", "ICT is ready for business continuity.", "continuity plans and test results"),
    _iso("5.31", "Legal, statutory and contract requirements are known.", "the register of requirements"),
    _iso("5.32", "Intellectual-property rights are respected.", _DOC),
    _iso("5.33", "Records are protected.", _DOC),
    _iso("5.34", "Privacy and personal data are protected.", "the data-protection records"),
    _iso("5.35", "Information security is reviewed independently.", "the last independent review"),
    _iso("5.36", "Policies and standards are followed and checked.",
         "compliance reviews (Kratos's reports can be one input)"),
    _iso("5.37", "Operating procedures are written down.", _DOC),
    _iso("6.1", "People are screened before they join.", _REC),
    _iso("6.2", "Employment terms cover security.", "the contract terms"),
    _iso("6.3", "People are trained and aware of security.", "training records"),
    _iso("6.4", "There is a disciplinary process for breaches.", _DOC),
    _iso("6.5", "Duties continue after people leave or change role.", _DOC),
    _iso("6.6", "Confidentiality agreements are in place.", "the signed agreements"),
    _iso("6.7", "Remote working is secured.", _DOC),
    _iso("6.8", "People can report security events.", "the reporting channel and its use"),
    _iso("7.1", "Physical security perimeters are defined.", "a site description"),
    _iso("7.2", "Physical entry is controlled.", "entry-control records"),
    _iso("7.3", "Offices, rooms and facilities are secured.", "a site description"),
    _iso("7.4", "Premises are monitored.", "monitoring arrangements"),
    _iso("7.5", "Protection against physical and environmental threats.", "a site risk assessment"),
    _iso("7.6", "Work in secure areas is controlled.", _DOC),
    _iso("7.7", "Clear desk and clear screen.", _DOC),
    _iso("7.8", "Equipment is sited and protected.", "a site description"),
    _iso("7.9", "Assets off the premises are protected.", _DOC),
    _iso("7.10", "Storage media are handled safely.", _DOC),
    _iso("7.11", "Supporting utilities (power, cooling) are protected.", "the hosting provider's statement"),
    _iso("7.12", "Cabling is protected.", "the hosting provider's statement"),
    _iso("7.13", "Equipment is maintained.", "maintenance records"),
    _iso("7.14", "Equipment is disposed of or reused safely.", "disposal records"),
    _iso("8.1", "Endpoint devices of users are protected.", "the endpoint policy and device management records"),
    _iso("8.2", "Privileged access rights are limited and managed."),
    _iso("8.3", "Access to information is restricted."),
    _iso("8.4", "Access to source code is controlled.", "the code-hosting access settings"),
    _iso("8.5", "Authentication is secure."),
    _iso("8.6", "Capacity is managed.", "capacity monitoring (Kratos's disk projection covers only its own host)"),
    _iso("8.7", "Protection against malware."),
    _iso("8.8", "Technical vulnerabilities are managed."),
    _iso("8.9", "Configurations are set and kept secure."),
    _iso("8.10", "Information is deleted when no longer needed.", _DOC),
    _iso("8.11", "Data is masked where needed.", _DOC),
    _iso("8.12", "Data leakage is prevented.", "the data-loss controls in use"),
    _iso("8.13", "Information is backed up.", "backup jobs and restore tests for the monitored machines"),
    _iso("8.14", "Systems have enough redundancy.", "the redundancy design"),
    _iso("8.15", "Activity is logged and the logs are protected."),
    _iso("8.16", "Systems and networks are monitored for unusual activity."),
    _iso("8.17", "Clocks are synchronised."),
    _iso("8.18", "Privileged utility programs are controlled."),
    _iso("8.19", "Software installation on running systems is controlled."),
    _iso("8.20", "Networks are secured."),
    _iso("8.21", "Network services are secured."),
    _iso("8.22", "Networks are segregated.", "the network design"),
    _iso("8.23", "Web access is filtered.", "the web-filtering setup"),
    _iso("8.24", "Cryptography is used by set rules."),
    _iso("8.25", "Development follows a secure life cycle.", _DOC),
    _iso("8.26", "Application security requirements are set.", _DOC),
    _iso("8.27", "Systems are designed and engineered securely.", _DOC),
    _iso("8.28", "Code is written securely.", _DOC),
    _iso("8.29", "Security is tested in development and acceptance.", "test records"),
    _iso("8.30", "Outsourced development is supervised.", _REC),
    _iso("8.31", "Development, test and production are kept apart.", "the environment design"),
    _iso("8.32", "Changes are managed.", "change records"),
    _iso("8.33", "Test information is protected.", _DOC),
    _iso("8.34", "Audit testing doesn't harm running systems.", _DOC),
)


def _n(cid: str, text: str, person: str = "") -> Control:
    theme = "Art. 21(2)" if cid.startswith("21(2)") else "Reg. 2024/2690 Annex"
    return Control("nis2", cid, theme, text, person)


NIS2_CONTROLS: tuple[Control, ...] = (
    _n("21(2)(a)", "Risk analysis and information-system security policies.", "the risk analysis and the policies"),
    _n("21(2)(b)", "Incident handling.", "the incident-handling procedure and records (Kratos's logging checks cover only the technical part)"),
    _n("21(2)(c)", "Business continuity: backups, disaster recovery, crisis management.",
       "continuity and recovery plans, backup and restore-test records"),
    _n("21(2)(d)", "Supply-chain security with direct suppliers and service providers.", "supplier assessments"),
    _n("21(2)(e)", "Security in acquiring, developing and maintaining systems, incl. vulnerability handling.",
       "acquisition and development procedures (Kratos's checks cover patching and configuration only)"),
    _n("21(2)(f)", "Assessing whether the cybersecurity measures work.",
       "the assessment procedure (Kratos's reports can be one input)"),
    _n("21(2)(g)", "Basic cyber hygiene and cybersecurity training.", "training records and hygiene rules"),
    _n("21(2)(h)", "Use of cryptography and encryption.", "the cryptography policy (Kratos checks SSH and password hashing only)"),
    _n("21(2)(i)", "Human-resources security, access-control policies and asset management.",
       "HR and access-control procedures and the asset inventory (Kratos checks logins and privileges only)"),
    _n("21(2)(j)", "Multi-factor or continuous authentication and secured communications.",
       "where MFA is used and for which accounts"),
    _n("1", "Security policy for network and information systems.", _DOC),
    _n("2", "Risk-management policy.", _DOC),
    _n("3", "Incident handling.", "the incident-handling policy and records"),
    _n("3.2", "Monitoring and logging."),
    _n("4", "Business continuity and crisis management.", "continuity plans and backup records"),
    _n("4.2", "Backup and redundancy management.", "backup jobs and restore tests for the monitored machines"),
    _n("5", "Supply-chain security.", "supplier assessments"),
    _n("6", "Security in acquisition, development and maintenance.", "the procedures for buying, building and maintaining systems"),
    _n("6.3", "Configuration management."),
    _n("6.6", "Security patch management."),
    _n("6.7", "Network security."),
    _n("6.8", "Network segmentation.", "the network design"),
    _n("6.9", "Protection against malicious and unauthorised software."),
    _n("6.10", "Vulnerability handling and disclosure."),
    _n("7", "Assessing the effectiveness of risk-management measures.",
       "the assessment procedure (Kratos's reports can be one input)"),
    _n("8", "Basic cyber hygiene and security training.", "training records"),
    _n("9", "Cryptography."),
    _n("10", "Human-resources security.", _REC),
    _n("11", "Access control.", "the access-control policy"),
    _n("11.2", "Management of access rights."),
    _n("11.3", "Privileged and system-administration accounts."),
    _n("11.6", "Authentication."),
    _n("11.7", "Multi-factor authentication.", "where MFA is used and for which accounts"),
    _n("12", "Asset management.", "the asset inventory"),
    _n("12.4", "Asset inventory.", "the asset inventory (Kratos's machine list helps, but isn't the whole thing)"),
    _n("13", "Environmental and physical security.", "the hosting provider's statement"),
)

# The real numbering, for the mapping-integrity test: Art. 21(2)(a)-(j); the Annex's
# sections 1-13 and their subsections (2024/2690 as published).
NIS2_ARTICLE_LETTERS = tuple("abcdefghij")
NIS2_ANNEX_SECTIONS: dict[str, int] = {"1": 2, "2": 3, "3": 6, "4": 3, "5": 2, "6": 10, "7": 0, "8": 2, "9": 0,
                                        "10": 4, "11": 7, "12": 5, "13": 3}

CONTROLS: dict[str, dict[str, Control]] = {
    "iso27001": {c.id: c for c in ISO_CONTROLS},
    "nis2": {c.id: c for c in NIS2_CONTROLS},
}


def valid_nis2_ref(ref: str) -> bool:
    if ref.startswith("21(2)(") and ref.endswith(")"):
        return ref[6:-1] in NIS2_ARTICLE_LETTERS and len(ref) == 8
    head, _, sub = ref.partition(".")
    if head not in NIS2_ANNEX_SECTIONS:
        return False
    return not sub or (sub.isdigit() and 1 <= int(sub) <= NIS2_ANNEX_SECTIONS[head])


def control(framework: str, cid: str) -> Control | None:
    return CONTROLS.get(framework, {}).get(cid)


def iso_ids() -> list[str]:
    return [c.id for c in ISO_CONTROLS]
