"""Durable assessment orchestration.

PostgreSQL is the authoritative state and the queue only delivers a nudge, so
duplicate or out-of-order delivery cannot duplicate evidence or corrupt a run.
"""
