"""Per-run notes storage — mirrored to {state_dir}/notes.json."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


_notes_storage: dict[str, dict[str, Any]] = {}
_VALID_NOTE_CATEGORIES = ["general", "findings", "methodology", "questions", "plan", "wiki"]
_notes_lock = threading.RLock()
_DEFAULT_CONTENT_PREVIEW_CHARS = 280

_notes_path: Path | None = None
_vault_path: Path | None = None
_current_scan_id: str | None = None


def hydrate_notes_from_disk(state_dir: Path, scan_id: str | None = None) -> None:
    global _notes_path, _vault_path, _current_scan_id  # noqa: PLW0603
    _current_scan_id = scan_id

    from strix.config import load_settings
    settings = load_settings()

    if settings.memory.unified:
        base_dir = Path(settings.memory.base_dir).expanduser().resolve()
        _notes_path = base_dir / "memory" / "notes.json"
        _vault_path = base_dir / "vault"
    else:
        _notes_path = state_dir / "notes.json"
        _vault_path = state_dir.parent / "vault"

    with _notes_lock:
        _notes_storage.clear()
        if not _notes_path.exists():
            return
        try:
            data = json.loads(_notes_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "notes.json at %s is unreadable; starting with empty notes",
                _notes_path,
            )
            return
        if not isinstance(data, dict):
            return
        _notes_storage.update(
            {
                nid: note
                for nid, note in data.items()
                if isinstance(nid, str) and isinstance(note, dict)
            }
        )
        logger.info(
            "notes hydrated from %s (%d note(s))",
            _notes_path,
            len(_notes_storage),
        )
        generate_obsidian_graph_maps()


def generate_obsidian_graph_maps() -> None:
    """Regenerates the complete Obsidian vault .md notes, Index.md, and Graphiti Knowledge Map.md."""
    vault = _vault_path
    if vault is None:
        return

    with _notes_lock:
        try:
            # 1. Clean existing .md files safely to ensure we don't leave deleted notes
            if vault.exists():
                for item in list(vault.glob("**/*.md")):
                    with contextlib.suppress(OSError):
                        item.unlink()

            vault.mkdir(parents=True, exist_ok=True)

            # 2. Re-create all note files by category
            by_category: dict[str, list[tuple[str, str, dict[str, Any]]]] = {
                cat: [] for cat in _VALID_NOTE_CATEGORIES
            }

            for nid, note in _notes_storage.items():
                title = str(note.get("title", "")).strip()
                category = str(note.get("category", "general")).strip()
                if category not in by_category:
                    category = "general"

                # Sanitize title for filename
                safe_title = "".join(c for c in title if c not in r'\/:*?"<>|').strip()
                if not safe_title:
                    safe_title = nid

                category_dir = vault / category
                category_dir.mkdir(parents=True, exist_ok=True)
                note_file = category_dir / f"{safe_title}.md"

                # YAML Frontmatter
                tags_str = json.dumps(note.get("tags", []))
                scans_str = json.dumps(note.get("scans", []))
                frontmatter = (
                    "---\n"
                    f'note_id: "{nid}"\n'
                    f'title: "{title}"\n'
                    f'category: "{category}"\n'
                    f"tags: {tags_str}\n"
                    f"scans: {scans_str}\n"
                    f'created_at: "{note.get('created_at', '')}"\n'
                    f'updated_at: "{note.get('updated_at', '')}"\n'
                    "---\n\n"
                )

                body = str(note.get("content", ""))
                note_file.write_text(frontmatter + body, encoding="utf-8")
                by_category[category].append((safe_title, title, note))

            # 3. Generate Index.md (Obsidian Map of Content)
            index_lines = [
                "# Strix Scan Obsidian Vault",
                "",
                "Welcome to the autonomous security scan vault. Explore notes, findings, and knowledge graph links compiled dynamically by Strix AI hackers.",
                "",
                "## 🗺️ Knowledge Map",
                "- **[[Graphiti Knowledge Map]]**: A temporal visualization of all discovered assets, endpoints, vulnerabilities, and relationships.",
                "",
                "## 📂 Explore Notes by Category",
                "",
            ]

            for category in _VALID_NOTE_CATEGORIES:
                notes_in_cat = by_category[category]
                index_lines.append(f"### {category.capitalize()}")
                if not notes_in_cat:
                    index_lines.append("_No notes in this category yet._")
                else:
                    for safe_title, title, note in sorted(notes_in_cat, key=lambda x: x[1]):
                        tags = note.get("tags", [])
                        scans = note.get("scans", [])
                        tags_suffix = f" `{'` `'.join(tags)}`" if tags else ""
                        scans_suffix = f" _(Scans: {', '.join(scans)})_" if scans else ""
                        index_lines.append(f"- [[{safe_title}]] - {title}{tags_suffix}{scans_suffix}")
                index_lines.append("")

            (vault / "Index.md").write_text("\n".join(index_lines), encoding="utf-8")

            # 4. Generate Graphiti Knowledge Map.md
            from strix.tools.graphiti.tools import get_graphiti
            graph = get_graphiti()
            mermaid_chart = graph.to_mermaid()

            map_lines = [
                "# Graphiti Knowledge Map",
                "",
                "This temporal knowledge graph represents the active mental model of the Strix agents, linking discovered assets, endpoints, technologies, and vulnerabilities.",
                "",
                "## 🗺️ Visual Relationship Graph",
                mermaid_chart,
                "",
                "## 📂 Navigation",
                "- **[[Index]]**: Go back to the main vault index.",
            ]
            (vault / "Graphiti Knowledge Map.md").write_text("\n".join(map_lines), encoding="utf-8")

            logger.info("Obsidian Vault successfully updated at %s", vault)
        except Exception:
            logger.exception("Obsidian Vault update failed")


def _persist() -> None:
    path = _notes_path
    if path is None:
        return
    try:
        payload = json.dumps(_notes_storage, ensure_ascii=False, default=str)
        path.parent.mkdir(parents=True, exist_ok=True)
        with (
            _notes_lock,
            tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(path.parent),
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as tmp,
        ):
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
        generate_obsidian_graph_maps()
    except Exception:
        logger.exception("notes persist to %s failed", path)


def _filter_notes(
    category: str | None = None,
    tags: list[str] | None = None,
    search_query: str | None = None,
) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for note_id, note in _notes_storage.items():
        if category and note.get("category") != category:
            continue
        if tags:
            note_tags = note.get("tags", [])
            if not any(tag in note_tags for tag in tags):
                continue
        if search_query:
            search_lower = search_query.lower()
            title_match = search_lower in note.get("title", "").lower()
            content_match = search_lower in note.get("content", "").lower()
            if not (title_match or content_match):
                continue
        entry = note.copy()
        entry["note_id"] = note_id
        filtered.append(entry)
    filtered.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return filtered


def _to_note_listing_entry(
    note: dict[str, Any],
    *,
    include_content: bool = False,
) -> dict[str, Any]:
    entry = {
        "note_id": note.get("note_id"),
        "title": note.get("title", ""),
        "category": note.get("category", "general"),
        "tags": note.get("tags", []),
        "created_at": note.get("created_at", ""),
        "updated_at": note.get("updated_at", ""),
    }
    content = str(note.get("content", ""))
    if include_content:
        entry["content"] = content
    elif content:
        if len(content) > _DEFAULT_CONTENT_PREVIEW_CHARS:
            entry["content_preview"] = f"{content[:_DEFAULT_CONTENT_PREVIEW_CHARS].rstrip()}..."
        else:
            entry["content_preview"] = content
    return entry


def _create_note_impl(
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            if not title or not title.strip():
                return {"success": False, "error": "Title cannot be empty", "note_id": None}
            if not content or not content.strip():
                return {"success": False, "error": "Content cannot be empty", "note_id": None}
            if category not in _VALID_NOTE_CATEGORIES:
                return {
                    "success": False,
                    "error": (
                        f"Invalid category. Must be one of: {', '.join(_VALID_NOTE_CATEGORIES)}"
                    ),
                    "note_id": None,
                }

            # Merge identical findings/notes across runs when in unified memory mode
            existing_note_id = None
            for nid, existing in _notes_storage.items():
                if (
                    existing.get("title", "").strip().lower() == title.strip().lower()
                    and existing.get("category", "general") == category
                ):
                    existing_note_id = nid
                    break

            timestamp = datetime.now(UTC).isoformat()
            scan_id = _current_scan_id or "unknown"

            if existing_note_id is not None:
                note = _notes_storage[existing_note_id]

                # Merge scans
                scans_list = list(note.get("scans", []))
                if scan_id not in scans_list:
                    scans_list.append(scan_id)
                note["scans"] = scans_list

                # Merge tags
                existing_tags = set(note.get("tags", []))
                if tags:
                    existing_tags.update(tags)
                note["tags"] = list(existing_tags)

                # Merge content dynamically
                stripped_new_content = content.strip()
                if stripped_new_content not in note["content"]:
                    note["content"] = note["content"] + f"\n\n---\n*Added in scan {scan_id}:*\n" + stripped_new_content

                note["updated_at"] = timestamp
                note_id = existing_note_id
                message = f"Note '{title}' merged successfully under ID '{note_id}'"
            else:
                note_id = str(uuid.uuid4())[:6]
                note = {
                    "title": title.strip(),
                    "content": content.strip(),
                    "category": category,
                    "tags": tags or [],
                    "scans": [scan_id],
                    "created_at": timestamp,
                    "updated_at": timestamp,
                }
                _notes_storage[note_id] = note
                message = f"Note '{title}' created successfully"

        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to create note: {e}", "note_id": None}
        else:
            _persist()
            return {
                "success": True,
                "note_id": note_id,
                "message": message,
                "total_count": len(_notes_storage),
            }


def _list_notes_impl(
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            filtered = _filter_notes(category=category, tags=tags, search_query=search)
            notes = [_to_note_listing_entry(n, include_content=include_content) for n in filtered]
        except (ValueError, TypeError) as e:
            return {
                "success": False,
                "error": f"Failed to list notes: {e}",
                "notes": [],
                "filtered_count": 0,
                "total_count": 0,
            }
        return {
            "success": True,
            "notes": notes,
            "filtered_count": len(notes),
            "total_count": len(_notes_storage),
        }


def _get_note_impl(note_id: str) -> dict[str, Any]:
    with _notes_lock:
        try:
            if not note_id or not note_id.strip():
                return {"success": False, "error": "Note ID cannot be empty", "note": None}
            note = _notes_storage.get(note_id)
            if note is None:
                return {
                    "success": False,
                    "error": f"Note with ID '{note_id}' not found",
                    "note": None,
                }
            note_with_id = note.copy()
            note_with_id["note_id"] = note_id
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to get note: {e}", "note": None}
        else:
            return {"success": True, "note": note_with_id}


def _update_note_impl(
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    with _notes_lock:
        try:
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}
            note = _notes_storage[note_id]
            if title is not None:
                if not title.strip():
                    return {"success": False, "error": "Title cannot be empty"}
                note["title"] = title.strip()
            if content is not None:
                if not content.strip():
                    return {"success": False, "error": "Content cannot be empty"}
                note["content"] = content.strip()
            if tags is not None:
                note["tags"] = tags
            note["updated_at"] = datetime.now(UTC).isoformat()
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to update note: {e}"}
        else:
            _persist()
            return {
                "success": True,
                "note_id": note_id,
                "message": f"Note '{note['title']}' updated successfully",
                "total_count": len(_notes_storage),
            }


def _delete_note_impl(note_id: str) -> dict[str, Any]:
    with _notes_lock:
        try:
            if note_id not in _notes_storage:
                return {"success": False, "error": f"Note with ID '{note_id}' not found"}
            note = _notes_storage[note_id]
            note_title = note["title"]
            del _notes_storage[note_id]
        except (ValueError, TypeError) as e:
            return {"success": False, "error": f"Failed to delete note: {e}"}
        else:
            _persist()
            return {
                "success": True,
                "note_id": note_id,
                "message": f"Note '{note_title}' deleted successfully",
                "total_count": len(_notes_storage),
            }


@function_tool(timeout=30)
async def create_note(
    ctx: RunContextWrapper,
    title: str,
    content: str,
    category: str = "general",
    tags: list[str] | None = None,
) -> str:
    """Document an observation, finding, methodology step, or research note.

    Notes are visible to every agent in the same scan for the lifetime
    of the run; they live in-memory only and are cleared when the
    process exits.

    For actionable tasks, use ``todo`` instead — notes are for capturing
    information, todos are for tracking work.

    Categories:

    - ``general`` — default, anything that doesn't fit elsewhere.
    - ``findings`` — confirmed vulnerabilities or weaknesses (write
      these up promptly; you'll cite them when filing reports).
    - ``methodology`` — what you tried, what worked, what didn't —
      useful for the final scan report.
    - ``questions`` — open questions / things to come back to.
    - ``plan`` — multi-step plans you want to track.
    - ``wiki`` — long-form repository or target maps.

    Tags are free-form (e.g. ``["sqli", "auth", "critical"]``) — useful
    for later ``list_notes(tags=...)`` filtering.

    Args:
        title: Short headline.
        content: Full note body. Markdown is preserved.
        category: One of the categories above. Default ``"general"``.
        tags: Optional free-form tags.
    """
    return json.dumps(
        await asyncio.to_thread(_create_note_impl, title, content, category, tags),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def list_notes(
    ctx: RunContextWrapper,
    category: str | None = None,
    tags: list[str] | None = None,
    search: str | None = None,
    include_content: bool = False,
) -> str:
    """List existing notes — metadata-first by default.

    Filters compose: passing ``category="findings"`` and
    ``tags=["sqli"]`` returns notes that are *both* in the findings
    category AND have at least one of those tags.

    By default each entry includes a ``content_preview`` (first 280
    chars). Set ``include_content=True`` to get full bodies — useful
    when you need to scan many notes; expensive in tokens for large
    notes.

    Args:
        category: Filter by category.
        tags: Filter to notes that have any of these tags.
        search: Substring match against title and content.
        include_content: When False (default) entries have a preview;
            when True the full ``content`` is included.
    """
    return json.dumps(
        await asyncio.to_thread(
            _list_notes_impl,
            category=category,
            tags=tags,
            search=search,
            include_content=include_content,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def get_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Fetch one note by its 6-char ID. Returns the full content.

    Args:
        note_id: Note id from ``create_note`` or a ``list_notes`` entry.
    """
    return json.dumps(
        await asyncio.to_thread(_get_note_impl, note_id), ensure_ascii=False, default=str
    )


@function_tool(timeout=30)
async def update_note(
    ctx: RunContextWrapper,
    note_id: str,
    title: str | None = None,
    content: str | None = None,
    tags: list[str] | None = None,
) -> str:
    """Update a note's title, content, or tags.

    Pass ``None`` for any field you want left unchanged. Replacing
    ``content`` is a full overwrite — to append, fetch first with
    ``get_note``, concat, and pass the result.

    Args:
        note_id: Target note's 6-char ID.
        title: New title, or ``None`` to keep.
        content: New content, or ``None`` to keep.
        tags: New tags list, or ``None`` to keep.
    """
    return json.dumps(
        await asyncio.to_thread(
            _update_note_impl,
            note_id=note_id,
            title=title,
            content=content,
            tags=tags,
        ),
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def delete_note(ctx: RunContextWrapper, note_id: str) -> str:
    """Delete a note.

    Args:
        note_id: Note id to delete.
    """
    return json.dumps(
        await asyncio.to_thread(_delete_note_impl, note_id), ensure_ascii=False, default=str
    )
