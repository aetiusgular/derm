# The content of derm's v3 kit: an overlay on sbx's claude workload.
#
# sbx's v3 claude image has no Node (Docker Hardened Images, Debian 13;
# seen in the VM, integration w5's fix pass 11), and derm's hook is Node, so
# the kit carries one: the official Node 24 binary, pinned by the index
# digest of node:24-trixie-slim (read from Docker Hub on 7 Nov 2026; the
# same Debian 13 and glibc as the claude image). The install script checks
# it can run the hook before anything is registered.
FROM docker.io/library/node:24-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d AS node

FROM scratch
COPY --from=node /usr/local/bin/node /opt/derm-kit-src/node
COPY derm-kit/ /opt/derm-kit-src/
