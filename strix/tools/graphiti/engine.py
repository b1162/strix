"""Temporal Knowledge Graph Engine for Graphiti Memory."""

from __future__ import annotations

import json
import logging
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class TemporalKnowledgeGraph:
    """A thread-safe local temporal knowledge graph that mimics Zep's Graphiti.

    Tracks entities (nodes) and their relationships (edges) over time,
    with built-in support for generating Obsidian-friendly Mermaid visualizations.
    """

    def __init__(self, filepath: Path | None = None) -> None:
        self.filepath = filepath
        self._lock = threading.RLock()
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self.load()

    def load(self) -> None:
        """Load graph state from disk if available."""
        if self.filepath is None or not self.filepath.exists():
            return
        with self._lock:
            try:
                data = json.loads(self.filepath.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self.nodes = data.get("nodes", {})
                    self.edges = data.get("edges", [])
                    logger.info(
                        "Graphiti: loaded %d nodes and %d edges from %s",
                        len(self.nodes),
                        len(self.edges),
                        self.filepath,
                    )
            except Exception:
                logger.exception("Graphiti: failed to load graph from %s", self.filepath)

    def save(self) -> None:
        """Persist graph state to disk atomically."""
        if self.filepath is None:
            return
        with self._lock:
            try:
                payload = json.dumps(
                    {"nodes": self.nodes, "edges": self.edges},
                    ensure_ascii=False,
                    default=str,
                    indent=2,
                )
                self.filepath.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    encoding="utf-8",
                    dir=str(self.filepath.parent),
                    prefix=f".{self.filepath.name}.",
                    suffix=".tmp",
                    delete=False,
                ) as tmp:
                    tmp.write(payload)
                    tmp_path = Path(tmp.name)
                tmp_path.replace(self.filepath)
            except Exception:
                logger.exception("Graphiti: failed to save graph to %s", self.filepath)

    def add_node(self, name: str, node_type: str, attributes: dict[str, Any] | None = None) -> None:
        """Add or update an entity node in the graph."""
        name = name.strip()
        node_type = node_type.strip().lower()
        if not name:
            raise ValueError("Entity name cannot be empty")

        with self._lock:
            now = datetime.now(UTC).isoformat()
            if name in self.nodes:
                # Update existing
                self.nodes[name]["type"] = node_type
                if attributes:
                    self.nodes[name]["attributes"].update(attributes)
                self.nodes[name]["updated_at"] = now
            else:
                # Create new
                self.nodes[name] = {
                    "type": node_type,
                    "attributes": attributes or {},
                    "created_at": now,
                    "updated_at": now,
                }
            self.save()

    def add_edge(
        self,
        source: str,
        target: str,
        relationship: str,
        attributes: dict[str, Any] | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
    ) -> None:
        """Add a relationship edge between two entity nodes."""
        source = source.strip()
        target = target.strip()
        relationship = relationship.strip().lower()

        if not source or not target:
            raise ValueError("Source and target entity names cannot be empty")
        if not relationship:
            raise ValueError("Relationship label cannot be empty")

        with self._lock:
            # Ensure nodes exist
            if source not in self.nodes:
                self.add_node(source, "unknown")
            if target not in self.nodes:
                self.add_node(target, "unknown")

            now = datetime.now(UTC).isoformat()

            # Deactivate any duplicate ongoing relationship of the same type between these two nodes
            # (implements temporal validity / validity window update)
            if not valid_to:
                for edge in self.edges:
                    if (
                        edge["source"] == source
                        and edge["target"] == target
                        and edge["relationship"] == relationship
                        and edge.get("valid_to") is None
                    ):
                        edge["valid_to"] = now

            self.edges.append(
                {
                    "source": source,
                    "target": target,
                    "relationship": relationship,
                    "attributes": attributes or {},
                    "valid_from": valid_from or now,
                    "valid_to": valid_to,
                }
            )
            self.save()

    def search(self, query: str) -> dict[str, Any]:
        """Search nodes and edges matching the query."""
        query_lower = query.lower()
        matched_nodes: dict[str, dict[str, Any]] = {}
        matched_edges: list[dict[str, Any]] = []

        with self._lock:
            # Search nodes
            for name, node in self.nodes.items():
                if (
                    query_lower in name.lower()
                    or query_lower in node["type"]
                    or any(query_lower in str(v).lower() for v in node["attributes"].values())
                ):
                    matched_nodes[name] = node

            # Search edges
            for edge in self.edges:
                if (
                    query_lower in edge["source"].lower()
                    or query_lower in edge["target"].lower()
                    or query_lower in edge["relationship"]
                    or any(query_lower in str(v).lower() for v in edge["attributes"].values())
                ):
                    matched_edges.append(edge)
                    # Include edge endpoint nodes
                    if edge["source"] not in matched_nodes and edge["source"] in self.nodes:
                        matched_nodes[edge["source"]] = self.nodes[edge["source"]]
                    if edge["target"] not in matched_nodes and edge["target"] in self.nodes:
                        matched_nodes[edge["target"]] = self.nodes[edge["target"]]

        return {"nodes": matched_nodes, "edges": matched_edges}

    def to_mermaid(self) -> str:
        """Generate a beautiful, clean Mermaid diagram code block."""
        with self._lock:
            if not self.nodes:
                return "```mermaid\ngraph TD\n    empty[Knowledge Graph is empty]\n```"

            lines = ["graph TD", "    %% Node Definitions"]

            # Shapes/styles by node type
            # Obsidian graph nodes look stunning with customized shapes
            node_ids: dict[str, str] = {}
            for idx, name in enumerate(self.nodes):
                node_ids[name] = f"node{idx}"

            for name, node in self.nodes.items():
                nid = node_ids[name]
                ntype = node["type"]

                # Escape quotes in node name for safety
                escaped_name = name.replace('"', '\\"')

                if ntype == "vulnerability":
                    lines.append(f'    {nid}{{"💥 {escaped_name} (Vulnerability)"}}')
                elif ntype == "endpoint":
                    lines.append(f'    {nid}["🌐 {escaped_name} (Endpoint)"]')
                elif ntype in {"exploit", "payload"}:
                    lines.append(f'    {nid}["⚡ {escaped_name} (Exploit)"]')
                elif ntype in {"technology", "framework"}:
                    lines.append(f'    {nid}["🛠️ {escaped_name} ({ntype.capitalize()})"]')
                elif ntype in {"port", "service"}:
                    lines.append(f'    {nid}("🔌 {escaped_name} (Port)")')
                else:
                    lines.append(f'    {nid}["📝 {escaped_name} ({ntype.capitalize()})"]')

            lines.append("")
            lines.append("    %% Edge Relationships")

            # Keep track of added connections to avoid duplicating visual lines
            added_connections: set[tuple[str, str, str]] = set()

            for edge in self.edges:
                # Only show active edges (valid_to is None)
                if edge.get("valid_to") is not None:
                    continue
                src = edge["source"]
                tgt = edge["target"]
                rel = edge["relationship"]

                conn = (src, tgt, rel)
                if conn in added_connections:
                    continue
                added_connections.add(conn)

                src_id = node_ids.get(src)
                tgt_id = node_ids.get(tgt)
                if src_id and tgt_id:
                    lines.append(f"    {src_id} -->|{rel}| {tgt_id}")

            # Add custom styling for premium looks
            lines.append("")
            lines.append("    %% Styling Rules")
            lines.append(
                "    classDef vulnerability fill:#f43f5e,stroke:#be123c,stroke-width:2px,color:#fff;"
            )
            lines.append(
                "    classDef endpoint fill:#0ea5e9,stroke:#0369a1,stroke-width:2px,color:#fff;"
            )
            lines.append(
                "    classDef exploit fill:#eab308,stroke:#a16207,stroke-width:2px,color:#000;"
            )
            lines.append(
                "    classDef technology fill:#10b981,stroke:#047857,stroke-width:2px,color:#fff;"
            )

            for name, node in self.nodes.items():
                nid = node_ids[name]
                ntype = node["type"]
                if ntype in {"vulnerability", "endpoint", "exploit", "technology"}:
                    lines.append(f"    class {nid} {ntype};")

            mermaid_code = "\n".join(lines)
            return f"```mermaid\n{mermaid_code}\n```"
