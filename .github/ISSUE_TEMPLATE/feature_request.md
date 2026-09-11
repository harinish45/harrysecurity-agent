---
name: Feature Request
about: Suggest a new tool, agent, or capability
title: "[Feature] "
labels: enhancement
---

## What's the use case?

<!-- What are you trying to do that NEXUS-STRIKE doesn't support today? -->

## Which domain does this fit?

<!--
Pick one of the existing 30 domains under nexus/tools/ if it fits:
active_directory, ai_security, appsec, automation, automotive, blue_team,
cloud, compliance, cryptography, exploit_dev, forensics, hardware, iam,
incident_response, iot, malware, mobile, network, ot_ics, purple_team,
reconnaissance, red_team, reverse_engineering, rf_sdr, soc, threat_intel,
vuln_assessment, webapi, webapp, wireless

...or say if this needs a new domain / isn't a "tool" at all (e.g. an
orchestration, reporting, or dashboard change).
-->

## Proposed approach

<!--
If you have one — e.g. "a new nexus/tools/<domain>/<name>.py using library X
to do Y", or "extend the report_tone_agent to add a new template". Not
required, but it speeds up review.
-->

## Is this genuinely automatable, or does it need an honest degrade?

<!--
This project's convention (see CONTRIBUTING.md) is: if the capability truly
requires something the platform can't obtain on its own (hardware, a paid
API key, a licensed dataset, a live model to query), the tool should say so
via a STATUS_REQUIRES_* result rather than fake a finding. If your feature
request is in that category, say what it would need to fully activate.
-->

## Alternatives considered

<!-- Any existing tool/agent that's close but not quite it? -->
