"""Docker and Podman containers on a monitored machine (D.5).

- ``firewall`` -- a minimal model of iptables / nftables rules: does internet traffic
  reach a published port, and would the firewall have refused it on INPUT?
- ``judge`` -- CONT-001..008 from a container read;
- ``record`` -- read, confirm, judge, save ``containers/containers_<machine>.json``;
- ``packages`` -- packages inside running images, matched offline (PKG findings scoped
  to the image);
- ``logs`` -- container log files as a log source (dataset ``kratos.container``);
- ``findings`` / ``check`` / ``verify`` -- the findings-engine, collection and triage wiring.

Nothing here changes a container, a network or a firewall, and Kratos never asks for the
docker group or ``sudo docker``.
"""
