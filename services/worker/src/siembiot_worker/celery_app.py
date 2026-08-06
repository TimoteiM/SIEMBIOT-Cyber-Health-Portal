"""The Celery entrypoint.

    celery -A siembiot_worker.celery_app worker --queues assessments --beat

A module-level application object is what the Celery CLI expects, and it is the only
reason this file is separate from `tasks`: keeping the construction lazy there means the
rest of the worker package -- and every test in `tests/workflows/` -- stays usable with
no broker installed at all.
"""

from __future__ import annotations

from siembiot_worker.tasks import build_celery_app

app = build_celery_app()
