from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from . import __version__
from .dependency_inventory import unique_components
from .models import DependencyComponent


def cyclonedx_payload(components: tuple[DependencyComponent, ...] | list[DependencyComponent]) -> dict[str, object]:
    unique = unique_components(tuple(components))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "local-security-scanner",
                        "version": __version__,
                    }
                ]
            },
        },
        "components": [_component_payload(component) for component in unique],
    }


def render_cyclonedx(components: tuple[DependencyComponent, ...] | list[DependencyComponent]) -> str:
    return json.dumps(cyclonedx_payload(components), indent=2, ensure_ascii=False)


def _component_payload(component: DependencyComponent) -> dict[str, object]:
    payload: dict[str, object] = {
        "type": "container" if component.ecosystem == "Docker" else "library",
        "bom-ref": component.purl or f"{component.ecosystem}:{component.name}@{component.version}",
        "name": component.name,
        "version": component.version,
        "scope": component.scope,
        "purl": component.purl,
        "properties": [
            {"name": "sec-chk:ecosystem", "value": component.ecosystem},
            {"name": "sec-chk:target", "value": component.target},
            {"name": "sec-chk:source", "value": component.source},
            {"name": "sec-chk:path", "value": str(component.path)},
        ],
    }
    if component.line is not None:
        payload["properties"].append({"name": "sec-chk:line", "value": str(component.line)})  # type: ignore[index]
    return payload
