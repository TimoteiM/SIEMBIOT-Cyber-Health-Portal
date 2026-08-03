from __future__ import annotations

from collections.abc import Mapping
from typing import Any


class FrozenDict(dict[str, Any]):
    """A recursively frozen dict that remains JSON/Pydantic serializable."""

    @staticmethod
    def _immutable(*_: object, **__: object) -> None:
        raise TypeError("fixture_data_is_immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable  # type: ignore[assignment]
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable  # type: ignore[assignment]

    def __copy__(self) -> FrozenDict:
        return self

    def __deepcopy__(self, _: dict[int, object]) -> FrozenDict:
        return self


def deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return FrozenDict({str(key): deep_freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(deep_freeze(item) for item in value)
    return value


def json_compatible(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): json_compatible(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [json_compatible(item) for item in value]
    return value
