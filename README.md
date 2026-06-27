-:SECURITY GOVERNANCE AND COMPLIANCE AUTOMATION ENGINE (SGCAE):-
---- Governance Audit & Policy Compliance System ----

This Python-based system performs automated governance validation on user access records. It evaluates structured identity data against defined security policies to determine compliance posture and generate governance evidence artifacts.

The engine simulates how real governance systems inspect identity records, enforce security policies, and produce audit documentation for compliance reviews.

Core Capabilities: The system evaluates five primary governance policy domains:

Username Policy Validation: Ensures usernames comply with length requirements and character composition policies including uppercase rules, numeric presence, underscore usage, and symbol restrictions.

Password Policy Enforcement: Validates password complexity using configurable requirements such as minimum and maximum length, uppercase enforcement, numeric inclusion, and symbol requirements.

Login Security Controls: Detects policy violations related to excessive authentication failures and abnormal device access counts.

Multi‑Factor Authentication Governance: Verifies whether accounts comply with organizational MFA requirements or whether MFA policies are disabled or optional.

Session Management Compliance: Evaluates session idle time limits to detect users exceeding allowed inactivity thresholds.

Technical Implementation

Parsing and Validation:

Streaming JSON Processing: Uses the ijson streaming parser to safely process large user datasets without loading the entire file into memory.

Schema Enforcement: Each user record undergoes strict parameter validation including username, password, MFA status, device count, login failures, and session idle time.

Duplicate Identity Handling: Username collisions are automatically resolved using controlled suffix adjustments to maintain unique record identities during analysis.

Strict Typing: All policy and record attributes are validated against expected data types before policy evaluation begins.

State Management & Policy Evaluation

Binary Compliance Mapping: Each policy domain produces a binary result (pass/fail). These values form the compliance profile for each user.

Policy Alignment Engine: A structured validation layer compares user attributes directly against governance policy rules.

Risk Scoring: Each failed policy adds a risk score increment, allowing the system to categorize overall governance posture.

Execution Workflow

The engine executes in three operational stages:

Stage I — Policy Verification: Validates that the policy configuration file is complete and correctly structured.

Stage II — Record Validation: Processes each user record using streaming parsing and evaluates it against all governance policies.

Stage III — Governance Reporting: Aggregates violations, calculates governance risk scores, and generates audit artifacts.

Usage Execute the script via CLI with both the policy file and user records file:

python sgcae.py <policies.json> <system_state.json>

Both input files must be valid JSON files with names containing alphanumeric characters and underscores.

Configuration Parameters

The governance engine operates using policy definitions defined in the policy configuration file. Example policy parameters include:

Username Policy: minimum length, maximum length, uppercase rules, numeric requirements, underscore policy, symbol policy.

Password Policy: complexity rules including uppercase, numbers, symbols, and length requirements.

Login Policy: maximum allowed failed login attempts and maximum device registrations.

Access Policy: MFA enforcement requirement.

Session Policy: maximum idle session duration.

Output Generation

The system produces four governance artifacts after execution:

Governance Audit Report: A human‑readable audit document detailing policy violations and governance status per user.

Compliance Matrix: A JSON structured matrix mapping each user to pass/fail results across all policy domains.

Governance Evidence Log: A compact evidence log containing audit identifiers, violation counts, and risk scores.

Clean User Records: A record file containing all users who passed every governance policy check.

Governance Risk Classification

Each user receives a governance status based on accumulated risk score:

COMPLIANT: No policy violations detected.

PARTIAL: Minor governance deviations.

NON‑COMPLIANT: Multiple policy violations observed.

CRITICAL: Severe governance exposure indicating high security risk.

Data Integrity Safeguards

The system includes several defensive controls to maintain analysis integrity:

Record Limit Protection: A maximum user threshold prevents uncontrolled resource consumption.

Malformed Record Detection: Any structurally invalid record triggers controlled interruption of Stage II processing.

Streaming Fail‑Safe Handling: Partial processing results are preserved even if parsing errors occur.

Execution Boundary Controls: Stage‑based validation ensures policy failures or corrupted inputs cannot silently propagate through the system.

This project was created as a learning exercise to explore practical implementation of security governance validation, compliance auditing, and policy‑driven access control analysis using Python.
