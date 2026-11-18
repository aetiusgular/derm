# The content of derm's v3 kit for a command-hook agent: an overlay on the
# agent's own sbx workload.
#
# sbx's v3 images for Copilot CLI, Droid and Kiro have no Node on PATH
# (seen in the VMs on the box, sbx 0.51.0, 17 Nov 2026), and derm's hook is
# Node, so the kit carries one: the same official Node 24 binary, by the
# same index digest, as derm's Claude Code kit
# (packaging/sbx-kit/claude/derm-gate-claude.dockerfile; a test holds the
# two lines equal). The images are Docker Hardened Images on Debian, as the
# claude image is. The install script checks it can run the hook before
# anything is registered.
FROM docker.io/library/node:24-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d AS node

FROM scratch
COPY --from=node /usr/local/bin/node /opt/derm-kit-src/node
COPY derm-kit/ /opt/derm-kit-src/
