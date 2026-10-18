# Security

## Reporting a vulnerability

**Not in a public issue, please.** Report it privately through GitHub -
[**Report a vulnerability**](https://github.com/AbdelmonemAwad/os-netreport/security/advisories/new),
on the Security tab - where only you and the owner see it, and the fix can be prepared before anything is
public. Without a GitHub account, write to **eg2@live.com**. Either way, include:

- what is affected - the report builder, the e-mail it sends, its page and its configd actions;
- the appliance, the version you installed, and the OPNsense version;
- how to reproduce it, and what you saw.

This is one person's project, worked on in the evenings: expect an answer within days, not hours.
A fix is made in a pull request and the reporter credited in it, unless they ask not to be.

## What is supported

The newest version on `main`, and the newest release where there are releases. Fixes go there,
with no backports.

## Worth knowing before you report

- **It e-mails a summary of the network.** A report sent to anyone but the recipients the owner set, or carrying more than its page says it does, is a privacy problem - report it here.
- Never paste a real report into a public issue: it names the network's machines.
- **Never send a configuration backup.** It holds keys and passwords.
