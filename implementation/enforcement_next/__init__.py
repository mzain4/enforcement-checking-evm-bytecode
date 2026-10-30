"""Dependency- and role-aware property analysis over Gigahorse facts.

`implementation/enforcement/` is the inherited engine and is imported, never modified. This package adds
three rules with feature flags so that each refinement can be ablated:

* `callresult_dependency` - follow an external call's success value through comparisons and branches and
  decide whether the failing outcome is actually rejected.
* `origin_role` - decide whether an ORIGIN-derived value is used as an identity credential rather than as a
  caller-equivalence test.
* `guard_dominance` - require a caller guard to dominate the protected effect on its authorised edge.

With every flag off the package is a presence-only rule set over the same facts.
"""
from .analyze import DEFAULT_FLAGS, FLAG_NAMES, analyse_facts

__all__ = ['DEFAULT_FLAGS', 'FLAG_NAMES', 'analyse_facts']
