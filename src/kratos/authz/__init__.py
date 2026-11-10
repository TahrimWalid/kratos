"""Users, roles, scopes and the audit trail (docs/phaseD/D.7).

    from kratos import authz
    authz.require(actor, authz.P.INVESTIGATE, machine, data_dir=dd)

`require` is the one permission check; `check_run_access` re-checks at every read inside
a run; `acting_as` carries the actor with the run; `current_actor` reads it back.
"""
from kratos.authz import permissions as P
from kratos.authz.scope import scope_allows
from kratos.authz.check import (AccessRemoved, Denied, Principal, acting_as, check_run_access, current_actor,
                                is_local_owner, network_process, owner_actor, principal_of, require, require_person,
                                run_action, unattended_actor, unattended_refusal,
                                set_local_interface, set_network_process, token_id_of)

__all__ = ["P", "AccessRemoved", "Denied", "Principal", "acting_as", "check_run_access", "current_actor",
           "is_local_owner", "network_process", "owner_actor", "principal_of", "require", "run_action",
           "set_network_process", "set_local_interface", "token_id_of", "scope_allows", "require_person",
           "unattended_actor", "unattended_refusal"]
