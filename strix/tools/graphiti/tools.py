"""Agent tools for Temporal Knowledge Graph (Graphiti) memory."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.tools.graphiti.engine import TemporalKnowledgeGraph


logger = logging.getLogger(__name__)

_graph_lock = threading.RLock()
_graphiti_instance: TemporalKnowledgeGraph | None = None
_current_scan_id: str | None = None


def hydrate_graphiti_from_disk(state_dir: Path, scan_id: str | None = None) -> None:
    """Initialize and load the global Graphiti instance from the scan state directory."""
    global _graphiti_instance, _current_scan_id  # noqa: PLW0603
    _current_scan_id = scan_id

    from strix.config import load_settings
    settings = load_settings()

    if settings.memory.unified:
        filepath = Path(settings.memory.base_dir).expanduser().resolve() / "memory" / "graphiti.json"
    else:
        filepath = state_dir / "graphiti.json"

    with _graph_lock:
        _graphiti_instance = TemporalKnowledgeGraph(filepath)


def get_graphiti() -> TemporalKnowledgeGraph:
    """Retrieve the current active Graphiti instance, creating an in-memory one if uninitialized."""
    global _graphiti_instance  # noqa: PLW0603
    with _graph_lock:
        if _graphiti_instance is None:
            _graphiti_instance = TemporalKnowledgeGraph()
        return _graphiti_instance


def _add_graph_node_impl(name: str, node_type: str, attributes: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        graph = get_graphiti()
        scan_id = _current_scan_id or "unknown"

        attrs = dict(attributes or {})
        existing_scans = []
        if name in graph.nodes:
            existing_scans = list(graph.nodes[name].get("attributes", {}).get("scans", []))

        scans_list = list(existing_scans)
        if scan_id not in scans_list:
            scans_list.append(scan_id)
        attrs["scans"] = scans_list

        graph.add_node(name, node_type, attrs)

        # Update Obsidian graph and maps
        from strix.tools.notes.tools import generate_obsidian_graph_maps
        generate_obsidian_graph_maps()
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {
        "success": True,
        "message": f"Entity '{name}' of type '{node_type}' added/updated in the temporal knowledge graph.",
    }


def _add_graph_edge_impl(
    source: str,
    target: str,
    relationship: str,
    attributes: dict[str, Any] | None = None,
    valid_from: str | None = None,
    valid_to: str | None = None,
) -> dict[str, Any]:
    try:
        graph = get_graphiti()
        scan_id = _current_scan_id or "unknown"

        attrs = dict(attributes or {})
        existing_scans = []
        for edge in graph.edges:
            if (
                edge["source"] == source
                and edge["target"] == target
                and edge["relationship"] == relationship
                and edge.get("valid_to") is None
            ):
                existing_scans = list(edge.get("attributes", {}).get("scans", []))
                break

        scans_list = list(existing_scans)
        if scan_id not in scans_list:
            scans_list.append(scan_id)
        attrs["scans"] = scans_list

        graph.add_edge(source, target, relationship, attrs, valid_from, valid_to)

        # Update Obsidian graph and maps
        from strix.tools.notes.tools import generate_obsidian_graph_maps
        generate_obsidian_graph_maps()
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {
        "success": True,
        "message": f"Relationship '{source} --({relationship})--> {target}' added to the temporal knowledge graph.",
    }


def _search_graph_impl(query: str) -> dict[str, Any]:
    try:
        graph = get_graphiti()
        results = graph.search(query)
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {"success": True, "results": results}


def _view_graph_summary_impl() -> dict[str, Any]:
    try:
        graph = get_graphiti()
        mermaid_code = graph.to_mermaid()
        nodes_count = len(graph.nodes)
        active_edges_count = len([e for e in graph.edges if e.get("valid_to") is None])
    except Exception as e:
        return {"success": False, "error": str(e)}
    return {
        "success": True,
        "nodes_count": nodes_count,
        "active_edges_count": active_edges_count,
        "mermaid_chart": mermaid_code,
    }


@function_tool(timeout=30, strict_mode=False)
async def add_graph_node(
    ctx: RunContextWrapper,
    name: str,
    node_type: str,
    attributes: dict[str, Any] | None = None,
) -> str:
    """Record an entity (node) in the temporal knowledge graph memory.

    Use this to document important discovered components, technologies, endpoints,
    or vulnerabilities so they are saved in structured memory across agents.

    Node Types:
    - ``endpoint`` — Web URLs or API paths (e.g. ``/api/v1/auth``).
    - ``vulnerability`` — Discovered security gaps (e.g. ``CWE-89 SQL Injection``).
    - ``exploit`` — exploit scripts, PoCs, or payloads used.
    - ``technology`` — server/app tech stack details (e.g. ``NestJS``, ``PostgreSQL``).
    - ``port`` — open TCP/UDP ports or services.
    - ``general`` — other relevant concepts/findings.

    Args:
        name: Unique short name/ID of the entity (e.g. "/api/v1/users", "CWE-89 SQLi").
        node_type: Type of the node (from types above).
        attributes: Key-value attributes describing the node (e.g. ``{"version": "1.2", "status": "active"}``).
    """
    return json.dumps(
        await asyncio.to_thread(_add_graph_node_impl, name, node_type, attributes),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30, strict_mode=False)
async def add_graph_edge(
    ctx: RunContextWrapper,
    source: str,
    target: str,
    relationship: str,
    attributes: dict[str, Any] | None = None,
    valid_from: str | None = None,
    valid_to: str | None = None,
) -> str:
    """Record a relationship (edge) between two entities in the knowledge graph.

    Graphiti edges are temporally-aware. Adding a new active edge with the same
    relationship name will automatically deprecate/mark the previous one as inactive
    to maintain a fresh and correct mental model.

    Common Relationships:
    - ``vulnerable_to`` — endpoint/technology is vulnerable to a specific vulnerability.
    - ``exploits`` — an exploit/payload targets a vulnerability/endpoint.
    - ``runs`` — a server runs a technology.
    - ``contains`` — an endpoint or folder contains another.
    - ``depends_on`` — a component depends on another.

    Args:
        source: Name of the source entity (must exist, or will be created automatically).
        target: Name of the target entity (must exist, or will be created automatically).
        relationship: Name of the relationship (from common list or custom).
        attributes: Metadata/attributes describing the relationship.
        valid_from: ISO datetime when verified. Defaults to current time.
        valid_to: ISO datetime when relationship ended (leave empty/None for currently active).
    """
    return json.dumps(
        await asyncio.to_thread(
            _add_graph_edge_impl,
            source,
            target,
            relationship,
            attributes,
            valid_from,
            valid_to,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def search_graph(ctx: RunContextWrapper, query: str) -> str:
    """Query the temporal knowledge graph to search for nodes or relationships.

    Args:
        query: Search term to query node names, types, relationships, or attributes.
    """
    return json.dumps(
        await asyncio.to_thread(_search_graph_impl, query),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def view_graph_summary(ctx: RunContextWrapper) -> str:
    """Retrieve a summary of the temporal knowledge graph, including a Mermaid flowchart.

    Use this to see an overview of the agent's complete mental model of the target.
    """
    return json.dumps(
        await asyncio.to_thread(_view_graph_summary_impl),
        ensure_ascii=False,
        default=str,
    )
