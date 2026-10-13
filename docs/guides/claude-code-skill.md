---
title: "Claude Code skill"
description: "Install the bundled Claude Code skill and let it walk you through each flagged dependency."
---

# Claude Code skill

licenseal ships a [Claude Code](https://claude.com/claude-code) skill that drives the [review workflow](review-findings.md) interactively. Install it into the project, then invoke `/licenseal-review` in Claude Code:

```bash
licenseal install-skill                  # <project>/.claude/skills/licenseal-review/SKILL.md
licenseal install-skill --path ../other  # install into another project directory
licenseal install-skill --force          # overwrite a hand-edited skill
```

The skill runs `licenseal check`, walks through warnings, violations, unknown licenses, and [analysis gaps](../concepts/check-failures.md#analysis-gaps), and asks how your project is distributed, hosted, modified, or shipped. It fills `licenseal.review.toml` from your decisions, only when there is a concrete reason that a reviewer can check, keeps genuine incompatibilities flagged, and re-runs the check so what is still flagged is explicit.

<figure markdown>
![Claude Code licenseal review skill asking whether MPL dependencies were modified before marking them reviewed](../assets/claude-skill-question.png){ .screenshot }
</figure>

The skill is written only inside the project (`.claude/skills/`), never globally, so it can be committed with the code it audits. Claude Code discovers it automatically.

## Keeping the skill current

The installed `SKILL.md` is a snapshot, so upgrading the package does not update it. When the bundled skill changes in a release, the next `licenseal check` prints a one-line reminder, and re-running `install-skill` rewrites an unedited install in place (no `--force` needed).
