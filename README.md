# honeypot

A skill for Claude Code and Codex that sets up a honeypot (a decoy) for your app and proves its alert reaches you.

You tell it where your app runs (Vercel, Supabase, Render, Railway, AWS, your own server) and what you want to catch:
someone using a copied cloud key, opening a private document, probing a web route, poking around your network,
changing decoy files, or calling an AI tool your agent should never need. It picks one decoy that fits, walks you
through it one checked step at a time, and only calls the job done when three things are proven:

1. the decoy is running,
2. a harmless test triggered it,
3. the alert landed where you chose (email, Slack, Discord or a webhook).

## Install

Paste this line into Claude Code or Codex:

```text
Clone https://github.com/christianjohnston-ai/honeypot into ~/honeypot (git pull if it is already there), read ~/honeypot/honeypot-setup/README.md, and install the honeypot-setup skill for this agent without overwriting an existing one.
```

Or do it by hand:

```sh
git clone https://github.com/christianjohnston-ai/honeypot.git ~/honeypot

# Claude Code
mkdir -p ~/.claude/skills
test ! -e ~/.claude/skills/honeypot-setup && cp -R ~/honeypot/honeypot-setup ~/.claude/skills/honeypot-setup

# Codex
mkdir -p ~/.agents/skills
test ! -e ~/.agents/skills/honeypot-setup && cp -R ~/honeypot/honeypot-setup ~/.agents/skills/honeypot-setup
```

If the agent does not see the skill yet, restart it.

## Use

In Claude Code:

```text
/honeypot-setup Help me choose a honeypot or honeytoken for my app. Use guided mode.
```

In Codex:

```text
$honeypot-setup Help me choose a honeypot or honeytoken for my app. Use guided mode.
```

Later you can say "test my alerts", "resume setup", "change where alerts go", "why didn't I get notified?" or
"remove this honeypot".

## What happens after the alarm

The skill's job ends when the alert reaches you. On purpose, it never blocks anyone, revokes a key or shuts a system
down by itself: a decoy can fire for an innocent reason (a scanner, a backup job, a teammate who opened the wrong
file), and an automatic shutdown can take your own app offline.

If you want Claude to take the next step with you, add this optional response. Save the text below as
`~/.claude/commands/honeypot-respond.md` (don't overwrite one you already have):

```text
---
description: A honeypot alert fired. Investigate it, propose shut-down steps, then wait for my approval.
---
A honeypot alert just fired:

$ARGUMENTS

Do not change anything yet.
1. Look up the source IP address: who owns it, its network and country, and whether it belongs to a known scanner, VPN or cloud provider.
2. Search my logs for that IP and for the decoy's name over the last 7 days. List every request it made.
3. Write what you found to incident-<date>.md in this folder: what was touched, when, from where, and how sure you are that it is an attack and not a false alarm.
4. Propose the shut-down steps that fit, numbered, each with the exact command and how to undo it. For example: block the IP at the firewall or WAF, rotate any real key or password stored near the decoy, end active sessions, take the affected service offline.
Then stop. Run a step only after I reply "approve" with its number.
```

When an alert lands, open Claude Code in your app's folder and type `/honeypot-respond`, then paste the alert. Claude
looks up the IP, writes what it found and lines up the shut-down steps. Nothing is blocked until you reply
`approve 1` (or `approve 1 2 3`).

## What is in this repository

- `honeypot-setup/` is the skill: `SKILL.md`, one reference file per kind of decoy, templates, a small local alert
  helper (`scripts/decoyctl.py`, Python standard library only) and its tests. Its own [README](honeypot-setup/README.md)
  has the full install, test and removal notes.
- `research/` holds the build notes and public-source data behind the recommendations. The skill does not need it to run.

## Good to know

- It is defensive only: use it on apps and systems you own or are allowed to run.
- A decoy only sees what touches it. No alert does not mean nothing happened.
- Some options use a hosted service (Canarytokens) or a separate Linux machine and can cost money. The skill asks
  before it creates anything billable or public.
- Deleting the skill folder does not stop a decoy, disable a token or cancel costs. Ask the skill to remove the
  honeypot first.

MIT licensed, see [LICENSE](LICENSE). [honeypot-setup/NOTICE.md](honeypot-setup/NOTICE.md) lists the third-party
projects it refers to and their licences.
