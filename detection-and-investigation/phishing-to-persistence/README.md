# Phishing to Persistence

## Objective

Demonstrate how an attacker can execute code, abuse PowerShell, download content, and establish persistence while generating telemetry that can be detected and investigated.

## Attack Chain

MSHTA Execution
↓
PowerShell Execution
↓
Encoded PowerShell
↓
Download Activity
↓
Scheduled Task Creation
↓
Registry Run Key Persistence

## Status

* Attack Simulated
* Sysmon Events Validated
* Logs Ingested into Elastic
* Alerts Triggered
* Screenshots Collected

## Investigation

This investigation documents the attack lifecycle, generated telemetry, detection opportunities, evidence collected, and analyst findings.
