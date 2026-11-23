# Honeypot Setup — Claude Code and Codex skill

This reusable skill interviews the person running it, chooses a decoy that fits their application, guides setup and confirms a matching notification. It supports beginners and developers, guided and assisted operation, resuming setup, testing, changing alert destinations, troubleshooting and removal.

Start with hosted Canarytokens when a specific callback or credential-use mechanism covers the goal and no extra server is wanted. Use isolated OpenCanary for network services. Application and AI/MCP routes require the stated placement and integration checks. None of these routes guarantees discovery of every compromise.

## Install locally

Extract the archive and open a terminal in the directory containing the `honeypot-setup` folder. Review its [SKILL.md](SKILL.md), scripts and [license](LICENSE) before use. The following installs **the same portable skill** into either agent; it does not deploy a honeypot.

Claude Code, personal installation:

```sh
mkdir -p "$HOME/.claude/skills"
test ! -e "$HOME/.claude/skills/honeypot-setup" && test ! -L "$HOME/.claude/skills/honeypot-setup" && cp -R ./honeypot-setup "$HOME/.claude/skills/honeypot-setup"
```

Codex, personal installation:

```sh
mkdir -p "$HOME/.agents/skills"
test ! -e "$HOME/.agents/skills/honeypot-setup" && test ! -L "$HOME/.agents/skills/honeypot-setup" && cp -R ./honeypot-setup "$HOME/.agents/skills/honeypot-setup"
```

These commands refuse to overwrite an existing skill. If already installed, compare versions and back up the existing folder before replacing it. Alternatively, install in a project at `.claude/skills/honeypot-setup` for Claude Code or `.agents/skills/honeypot-setup` for Codex. Keep private runtime state outside both skill folders and version control.

The current official local-skill documentation specifies the above paths. Claude Code exposes `/honeypot-setup`; Codex CLI/IDE supports `$honeypot-setup` and `/skills`. If discovery has not refreshed, restart the agent. [Claude Code skills](https://code.claude.com/docs/en/skills), [Codex skill guide](https://learn.chatgpt.com/docs/build-skills) (reviewed 2026-11-23).

## Invoke

In Claude Code:

```text
/honeypot-setup Help me choose a honeypot or honeytoken for my app. Use guided mode.
```

In Codex:

```text
$honeypot-setup Help me choose a honeypot or honeytoken for my app. Use guided mode.
```

Beginner example: “My site uses Vercel and Supabase. I want an email if someone uses a planted secret. I don't know Docker.” The skill asks only the next useful questions and explains exactly what a trigger means.

Follow-ups: “resume setup,” “test my alerts,” “change where alerts go,” “why didn't I get notified?”, or “remove this honeypot.” Supply the nonsecret deployment profile location if it is not already in the conversation. Do not paste credentials, complete `.env` files or token-management URLs into chat.

## Package and compatibility

`SKILL.md` is the shared entrypoint. `references/` contains route-specific instructions and research; templates and scripts support repeatable local operations. Load only the selected route. See [platform constraints](references/platforms.md) before prescribing cloud commands.

The package follows the [Agent Skills specification](https://agentskills.io/specification): a matching lowercase directory/name, YAML `name` and `description`, Markdown instructions and relative supporting-file links. It does not depend on Claude-specific hooks, subagent syntax, dynamic shell expansion or broad `allowed-tools` grants. Optional Codex UI metadata does not change the portable workflow. Agents supporting the standard can read it, but tool availability, shell execution, confirmation behavior and installation paths remain host-specific.

Claude Code is the primary target; Codex is a supported instruction-format target. This build validates the package and local helpers; it does not claim that a fresh Claude Code session, every cloud deployment, or a third-party inbox has been exercised. Consult the delivered validation report for the executed/simulated/documentation-only distinction. Ordinary Claude web chat or Codex cloud sessions do not automatically receive files installed in your machine's personal skill directory.

The skill itself needs no server to run an interview. Selected helpers require their documented interpreter; deployment requirements depend on the chosen route. An account subscription for an agent, provider hosting, email/SMS, queues and LLM use can incur separate costs.

Run the bundled local tests from the installed skill directory:

```sh
python3 -m unittest discover -s tests -v
# Optional: Node 20+ checks the inline application/n8n recipes with mocks.
node tests/test_reference_snippets.mjs
```

The Python helpers target local machines and isolated persistent Linux hosts. Passing local tests does not establish serverless compatibility or successful cloud notification delivery.

## Operate and remove

Complete all three acceptance checks: mechanism running, harmless trigger observed, matching alert received. An HTTP success or a running container alone is insufficient. Without verified receipt, the profile remains **configured, delivery unverified**.

Removing this skill directory only uninstalls the agent instructions. It does not stop a honeypot, disable a token, delete a cloud resource or cancel recurring costs. Invoke the removal workflow first, verify resource identity and follow the recorded handoff/rollback instructions.
