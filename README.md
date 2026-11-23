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
