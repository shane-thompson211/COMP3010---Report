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

Q1 – IAM user identification

Answer: 
•	bstoll
•	btun
•	splunk_access
•	web_admin

SPL Query:
index=botsv3 sourcetype="aws:cloudtrail" | stats count by userIdentity.userName

SOC Analysis: 
A tier 1 SOC analyst will see the results from the query and must differentiate between service accounts and human users. Both “splunk_access” and “web_admin” seem to be obvious service accounts while “bstoll” has very high activity at (615 events) compared to “btun” at (73 events). This activity will require further investigation by a tier 2 analyst where deeper inspection of each user accounts activity. If suspicious activity is found like compromised credentials or unusual behaviour, then the user can be disabled.

Q2- multi-factor-authentication

Answer: 
•	userIdentity.sessionContext.attributes.mfaAuthenticated

SPL Query:
index=botsv3 sourcetype="aws:cloudtrail" | table _time userIdentity.userName eventName userIdentity.sessionContext.attributes.mfaAuthenticated | dedup userIdentity.userName

SOC Analysis:
Operations performed without MFA significantly increase the chances of credential theft and unauthorised access. A tier 1 analysis will see the false flag from these users and regard them as suspicious and require further analysis. Deeper inspection will be done by a tier 2 analyst where login times, location and failed login attempts will be investigated. If malicious activity is found such as unauthorised file uploads, then tier 3 escalation is invoked to enforce mandatory MFA and update detection rules system wide.

Q3 – Processor Number used 

Answer: 
•	E5-2676
o	Full CPU - Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz

SPL Query:
Index=botsv3 sourcetype=hardware

SOC Analysis:
Monitoring hardware for inventory management is a crucial part of SOC operations. A tier 1 analyst will actively monitor the network to ensure that only authorised devices are present. If the entire system uses E5-2676 processors then it may not be suspicious however if a rouge system is found, then it can be immediately escalated to tier 2. If the suspect doesn’t have the correct authorisation, then the system must be blocked from the network. 
