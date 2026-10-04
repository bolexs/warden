# Security policy

Warden is a policy engine that decides whether a command or a file write may run.
A bypass, a false allow, or a way to make the hook exit without a decision is a
security issue.

## Reporting

Report privately through GitHub: open the Security tab of this repository and
choose "Report a vulnerability". Do not open a public issue.

You will get an acknowledgement within 72 hours and a fix or a decision within
30 days. Credit is given in the release notes unless you ask otherwise.

## Supported versions

Only the latest release receives fixes.

## Out of scope

Behaviour of the agents or shells that call warden, and the upstream shell
grammar's parsing of inputs warden already reports as unparsed.
