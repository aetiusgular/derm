# The content of derm's v3 kit for Codex: an overlay on sbx's codex
# workload. It holds only what derm run staged beside this file. The derm
# in it is a Linux build for the VM's architecture, which derm run picked
# and the install script runs once before it installs anything.
FROM scratch
COPY derm-kit/ /opt/derm-kit-src/
