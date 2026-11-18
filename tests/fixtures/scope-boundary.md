# Scope boundary

- app/web.py:handle TAINT: yes
- app/api.py:rpc TAINT: yes entry=POST /api/rpc
- app/internal.py:helper TAINT: no
