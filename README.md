# COMP3010---Report

Introduction

A Security Operations Centre is the central defence hub for modern organisations. They work by mitigating, identifying, and detecting cyber threats before they can cause any harm. A well-structured SOC integrates technologies, processes, and people to identify threats and limit any damage before it occurs (Vielberth, Böhm, Fichtinger, & Pernul, 2020).

This report documents an investigation into a fictitious brewing company, Frothly, that has been hit with various cyber-attacks. To simulate a real SOC environment, the Boss of the SOC v3 dataset is used.

The main goal is to utilise Splunk Enterprise, a security information and event management tool (SIEM), to ingest, index, and analyse security logs to find what has been compromised. The other objective is to find how the attack occurred and provide recommendations to strengthen Frothly’s security so further breaches cannot occur.

The scope of this report will focus on AWS CloudTrail logs, S3 access logs, endpoint logs, and the Windows source type. These will be used to search through the BOTSv3 dataset and identify any IAM anomalies, rogue devices, MFA violations, and altered access controls. The analysis is limited to the selected BOTSv3 200-level guided questions and does not attempt to find the full attack. It is assumed that the analysis is performed on a fully isolated virtual machine to maintain separation from the host machine and protect its integrity.
