# Interface screenshots

End-to-end captures of all three chela interfaces, for use in the README, SPEC,
and recovery guide. Each flow is shown step by step.

- Website: `chela.html` driven in Chrome (light theme).
- CLI: `chela-cli` output rendered as a terminal window.
- TUI: the interactive `chela` wizard captured from a real terminal.

## Website

### Split a BIP-39 seed

| Step | Screenshot |
|------|------------|
| Main menu | ![](web/01-main-menu.png) |
| Enter the seed phrase | ![](web/seed-1-enter-seed.png) |
| Seed entered (with optional passphrase) | ![](web/seed-2-seed-filled.png) |
| Choose the recovery rule | ![](web/seed-3-recovery-rule.png) |
| Pick a preset (3-of-5) | ![](web/seed-4-rule-preset.png) |
| Name the shareholders? | ![](web/seed-5-shareholders.png) |
| Choice made | ![](web/seed-6-shareholders-chosen.png) |
| Label the shares | ![](web/seed-7-label.png) |
| Label filled in | ![](web/seed-8-label-filled.png) |
| Confirm | ![](web/seed-9-confirm.png) |
| Shares generated | ![](web/seed-10-shares-generated.png) |

### Split a text password

| Step | Screenshot |
|------|------------|
| Enter the text | ![](web/text-1-enter-text.png) |
| Text entered (masked) | ![](web/text-2-text-filled.png) |
| Choose the recovery rule | ![](web/text-3-recovery-rule.png) |
| Pick a preset (2-of-3) | ![](web/text-4-rule-preset.png) |
| Name the shareholders? | ![](web/text-5-shareholders.png) |
| Choice made | ![](web/text-6-shareholders-chosen.png) |
| Label the shares | ![](web/text-7-label.png) |
| Label filled in | ![](web/text-8-label-filled.png) |
| Confirm | ![](web/text-9-confirm.png) |
| Shares generated | ![](web/text-10-shares-generated.png) |

### Recover from shares

| Step | Screenshot |
|------|------------|
| Enter the share code | ![](web/recover-1-card-code.png) |
| Share 1 code entered | ![](web/recover-2-card1-code.png) |
| Type share 1's words | ![](web/recover-3-card1-words.png) |
| Share 1 words entered | ![](web/recover-4-card1-words-filled.png) |
| Enter share 2's code | ![](web/recover-5-card2-code.png) |
| Share 2 code entered | ![](web/recover-6-card2-code-filled.png) |
| Type share 2's words | ![](web/recover-7-card2-words.png) |
| Share 2 words entered | ![](web/recover-8-card2-words-filled.png) |
| Secret recovered (hidden) | ![](web/recover-9-recovered.png) |
| Secret revealed | ![](web/recover-10-revealed.png) |

## CLI

| Step | Screenshot |
|------|------------|
| Help | ![](cli/1-help.png) |
| Split a text password | ![](cli/2-split-text.png) |
| Split a BIP-39 seed | ![](cli/3-split-seed.png) |
| Split with paper + JSON backups | ![](cli/4-split-files.png) |
| Recover from shares | ![](cli/5-recover.png) |
| A printed paper share | ![](cli/6-paper-card.png) |

## TUI

| Step | Screenshot |
|------|------------|
| Main menu | ![](tui/1-menu.png) |
| Enter the text | ![](tui/2-text-entry.png) |
| Name the backup | ![](tui/3-name.png) |
| Choose the recovery rule | ![](tui/4-recovery-rule.png) |
| Name the shareholders? | ![](tui/5-shareholders.png) |
| Add a note | ![](tui/6-note.png) |
| Confirm | ![](tui/7-confirm.png) |
| Record share 1 | ![](tui/8-share-card.png) |
| Record share 2 | ![](tui/9-share-card-2.png) |
| Split a BIP-39 seed | ![](tui/10-seed-entry.png) |
| Enter the passphrase | ![](tui/11-passphrase.png) |
