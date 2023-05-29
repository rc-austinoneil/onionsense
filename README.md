# OnionSense
A POC tool to query OPNsense/Elasticstack and block IPs if malicious. 

## Concept
Query the OPNsense Suricata log for allowed traffic, query Elasticstack using provided searches and enrich the IPs. If Virus Total says its >= the defined malicious score, add the IP to an OPNsense alias that blocks the IP via the firewall.

Provide output via Slack message and write to Google Sheets.

Think fail2ban but alot more effort.

## Tool Output
[OnionSense Tool Output - Google Sheet](https://docs.google.com/spreadsheets/d/1jHVO77KarBQtzuQhQEO3qFipCwqWGB0gK5iP1p6nypo/edit#gid=0)
