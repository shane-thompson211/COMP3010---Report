# COMP3010---Report

Introduction

A Security Operations Centre is the central defence hub for modern organisations. They work by mitigating, identifying, and detecting cyber threats before they can cause any harm. A well-structured SOC integrates technologies, processes, and people to identify threats and limit any damage before it occurs (Vielberth, Böhm, Fichtinger, & Pernul, 2020).

This report documents an investigation into a fictitious brewing company, Frothly, that has been hit with various cyber-attacks. To simulate a real SOC environment, the Boss of the SOC v3 dataset is used.

The main goal is to utilise Splunk Enterprise, a security information and event management tool (SIEM), to ingest, index, and analyse security logs to find what has been compromised. The other objective is to find how the attack occurred and provide recommendations to strengthen Frothly’s security so further breaches cannot occur.

The scope of this report will focus on AWS CloudTrail logs, S3 access logs, endpoint logs, and the Windows source type. These will be used to search through the BOTSv3 dataset and identify any IAM anomalies, rogue devices, MFA violations, and altered access controls. The analysis is limited to the selected BOTSv3 200-level guided questions and does not attempt to find the full attack. It is assumed that the analysis is performed on a fully isolated virtual machine to maintain separation from the host machine and protect its integrity.

SOC Roles & Incident Handling Reflection

A Security Operations Centre (SOC) helps protect organisations by continuously monitoring, detecting, analysing, and responding to cyber incidents and threats. In the context of the Frothly BOTSv3 scenario the hierarchical roles are as follows:

The first line of defence is the tier 1 analyst role and has the responsibility of monitoring the SIEM for alerts. In this investigation a tier 1 analyst would have been responsible for finding the initial MFA violations and identifying the user responsible “bstoll”. If any suspicious activity is found then a set procedure will be followed, and threats will be escalated to tier 2.

The tier 2 analyst dives deeper into the threats escalated to determine the scope of the breach. For the Frothly organisation it would involve investigating the CloudTrail logs and locating the endpoint linked to the compromised “bstoll” account. This stage focuses on the response rathe than pure detection. Containment actions such as isolating rouge devices and suspending the compromised user.

Tier 3 focusses on prevention and the root cause analysis. Outside of an active incident a tier 3 analyst would hunt for security breaches like the initiated file upload from the public S3 bucket. Additionally, this analyst would guide the path to recovery by implementing system wide improvements such as enforcing MFA and restricted IAM privileges for authorised users only.

Installation & Data Preparation
The investigation environment created using Splunk Enterprise and an Ubuntu Virtual Machine (VM). A VM was utilised to provide a secure environment separate from my host machine. Isolating environments when testing potentially dangerous datasets like BOTSv3 adheres to industry standard practices.

To prepare the host, the command apt update && apt upgrade were used to ensure the latest packages were installed. This ensures the OS is protected against known vulnerabilities. Splunk Enterprise were retrieved via the command line (wget) and installed into the /opt directory. Splunk was started from inside the /bin/splunk start while also agreeing to licence agreement. This opened the Splunk interface on port 8000.

The BOTSv3 dataset was retrieved from the GitHub repo and downloaded and extracted into the Downloads folder. The session in the terminal was elevated to admin privileges using sudo su. The cp (copy) command with the recursive flag (-r) were utilised to duplicate the extracted folder directly into the /opt/splunk/etc/apps directory. By doing this it protects the file’s structure to ensure the dataset loads correctly.

To test if the data can be accessed inside Splunk, the web interface was accessed by using the credentials created via the installation of Splunk. To verify the integrity of the ingestion, the search and reporting app was queried with index=botsv3. This successfully returned 2,083,056 events which confirms the SIEM is ready for analysis.
