"""``read_file``, ``write_file`` and ``list_dir`` — the three tools that touch the workspace.

**None of them resolves a path.** Each declares its path argument in ``ToolSpec.path_args``, so the
executor resolves it through the sandbox and substitutes the resolved path into the arguments the
handler receives (spec §11.3). A handler that resolved a candidate itself would be a second
containment implementation, checked against nothing, and the window the executor just closed would
reopen between the two resolutions. What arrives here is an absolute path already proven to be
inside the right root, and every operation below is performed on *that* value.

Because the handler is handed the **resolved** path rather than the model's string, nothing here
may echo its argument back verbatim: the resolved path names the workspace root, and refusal text
is part of the prompt surface (ADR-0053's last consequence). Every message a model sees is rendered
by :func:`_shown`, which is the path relative to the root that contains it — meaningful to a model
working in a workspace, and silent about where that workspace is.

The one place "inside the root" needs more than the executor's check is ``write_file``'s parent
creation: the resolved path's parents may not exist, and creating them walks components the
executor never resolved. A symlinked intermediate directory pointing outside the write root is this
phase's named failure mode, so the parents are created one level at a time and each level is
checked for being a symlink before the next is touched — see :func:`_make_parents`.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from baseaicore import ValidationError

from toolyard.containment import PathAccess, fully_resolve
from toolyard.types import (
    EgressClass,
    Reason,
    RiskClass,
    ToolOutput,
    ToolRefusal,
    ToolSpec,
    ToolStatus,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from toolyard.types import ToolContext, ToolHandler

__all__ = [
    "DEFAULT_MAX_LIST_ENTRIES",
    "DEFAULT_MAX_READ_BYTES",
    "MIN_READ_BYTES",
    "list_dir_tool",
    "read_file_tool",
    "write_file_tool",
]

DEFAULT_MAX_READ_BYTES: Final[int] = 1 << 20
"""How large a file ``read_file`` will load, in bytes.

A memory bound, and a different question from :data:`~toolyard.executor.DEFAULT_MAX_CONTENT_BYTES`,
which bounds what the *model* sees and truncates with a label. This one bounds what the process
loads, and exceeding it is a **refusal** rather than a truncation: a record's ``result_sha256`` is
a digest of the handler's whole output, so a handler that returned a prefix would make the
recorded digest a digest of the prefix, and the application's artifact would no longer match the
record that points at it. A megabyte is far above the 64 KiB a model sees by default, so the
ordinary large-file experience is still the executor's labelled truncation; this fires only for the
file no agent should be loading whole.
"""

DEFAULT_MAX_LIST_ENTRIES: Final[int] = 1_000
"""How many entries ``list_dir`` returns.

A directory with more is listed up to the cap and the last line says how many were omitted. A
listing is a rendering rather than a document — nothing hashes it against an original — so a
labelled partial listing costs nothing, which is why this cap truncates where ``read_file``'s
refuses.
"""

MIN_READ_BYTES: Final[int] = 1_024
"""Floor for a configured read cap: below this the tool could not return a useful file at all."""

MIN_LIST_ENTRIES: Final[int] = 1
"""Floor for a configured listing cap. Zero would make ``list_dir`` a tool that lists nothing."""

_PATH_PROPERTY: Final[Mapping[str, Any]] = {
    "type": "string",
    "minLength": 1,
    "maxLength": 4096,
}

_READ_SCHEMA: Final[Mapping[str, Any]] = {
    "type": "object",
    "properties": {
        "path": {
            **_PATH_PROPERTY,
            "description": "The file to read, relative to the workspace root or absolute.",
        }
    },
    "required": ["path"],
    "additionalProperties": False,
}

_LIST_SCHEMA: Final[Mapping[str, Any]] = {
    "type": "object",
    "properties": {
        "path": {
            **_PATH_PROPERTY,
            "description": "The directory to list, relative to the workspace root or absolute.",
        }
    },
    "required": ["path"],
    "additionalProperties": False,
}

_WRITE_SCHEMA: Final[Mapping[str, Any]] = {
    "type": "object",
    "properties": {
        "path": {
            **_PATH_PROPERTY,
            "description": "The file to write, relative to the workspace root or absolute.",
        },
        "content": {
            "type": "string",
            "description": (
                "The complete new contents of the file. The write replaces; it never appends."
            ),
        },
    },
    "required": ["path", "content"],
    "additionalProperties": False,
}


def _shown(target: Path, context: ToolContext) -> str:
    """Render a resolved path the way a model may see it: relative to the root that holds it.

    The handler is given the executor's resolved path, which is absolute and therefore names the
    workspace root. That root is exactly what refusal text may not carry, so every message a model
    reads goes through here first.

    Args:
        target: The resolved path.
        context: The invocation, for its roots.

    Returns:
        The path relative to the containing root, or the final component alone when no root
        contains it — which cannot happen for a path the executor resolved, and is the answer that
        reveals least if it ever does.
    """
    workspace = context.workspace
    for root in (workspace.write_root, *workspace.read_roots):
        try:
            resolved_root = fully_resolve(root)
        except (OSError, ValueError, RuntimeError):  # pragma: no cover - an unresolvable root
            continue
        if target == resolved_root:
            return "."
        if resolved_root in target.parents:
            return str(target.relative_to(resolved_root))
    return target.name  # pragma: no cover - unreachable for a path the executor resolved


def _refuse_os_error(exc: OSError, *, shown: str, target: Path) -> ToolRefusal:
    """Map an OS error onto its spec §13 row, telling the model what it can act on and no more.

    Args:
        exc: What the operation raised.
        shown: The workspace-relative path, for the model.
        target: The resolved path, for the record.

    Returns:
        The refusal. Every one of these is ``FAILED`` rather than ``REFUSED``: no rule of this
        package declined anything, the filesystem answered, and a different argument may well
        succeed (spec §13).
    """
    if isinstance(exc, FileNotFoundError):
        return ToolRefusal(
            Reason.FILE_NOT_FOUND,
            f"nothing exists at {shown!r}",
            status=ToolStatus.FAILED,
            record_detail=f"resolved to {target}",
        )
    if isinstance(exc, PermissionError):
        return ToolRefusal(
            Reason.PERMISSION_DENIED,
            f"the operating system refused access to {shown!r}",
            status=ToolStatus.FAILED,
            record_detail=f"resolved to {target}",
        )
    if isinstance(exc, IsADirectoryError | NotADirectoryError):
        return ToolRefusal(
            Reason.NOT_A_REGULAR_FILE,
            f"{shown!r} is not the kind of thing this tool handles",
            status=ToolStatus.FAILED,
            record_detail=f"resolved to {target}: {type(exc).__name__}",
        )
    return ToolRefusal(
        Reason.PERMISSION_DENIED,
        f"{shown!r} could not be opened ({type(exc).__name__})",
        status=ToolStatus.FAILED,
        record_detail=f"resolved to {target}: {exc.strerror or type(exc).__name__}",
    )


def _require_cap(name: str, value: int, minimum: int) -> int:
    """Validate a cap at construction, so a misconfigured tool fails at startup (spec §12).

    Args:
        name: The argument's name, for the message.
        value: What was passed.
        minimum: The floor.

    Returns:
        The validated cap.

    Raises:
        ValidationError: If it is not an ``int`` of at least ``minimum``. A cap is the caller's
            input, never a model's, so this raises rather than refusing.
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValidationError(
            f"{name} must be an int of at least {minimum}; got {value!r}.",
            details={"field": name, "minimum": minimum},
        )
    return value


class _ReadFile:
    """``read_file``'s handler. Holds its cap and nothing else."""

    __slots__ = ("_max_bytes",)

    def __init__(self, max_bytes: int) -> None:
        """Bind the handler to its read cap."""
        self._max_bytes = max_bytes

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput | ToolRefusal:
        """Read one file, whole, as UTF-8 text.

        Args:
            args: ``path``, already resolved by the executor and proven inside a readable root.
            context: The invocation, for rendering the path back to the model.

        Returns:
            The file's text, or a refusal: ``too_large`` when it exceeds the cap (the size is
            checked before the bytes are read, so the cap bounds what is loaded and not merely what
            is returned), ``not_utf8`` when the bytes are not text, ``not_a_regular_file`` for a
            directory or a device, and ``file_not_found`` or ``permission_denied`` from the
            filesystem. Every one of them is a returned value; nothing here raises for anything the
            model chose.
        """
        target = Path(str(args["path"]))
        shown = _shown(target, context)
        try:
            if not target.is_file():
                return ToolRefusal(
                    Reason.NOT_A_REGULAR_FILE if target.exists() else Reason.FILE_NOT_FOUND,
                    f"{shown!r} is not a readable file"
                    if target.exists()
                    else f"nothing exists at {shown!r}",
                    status=ToolStatus.FAILED,
                    record_detail=f"resolved to {target}",
                )
            size_bytes = target.stat().st_size
            if size_bytes > self._max_bytes:
                return ToolRefusal(
                    Reason.TOO_LARGE,
                    f"{shown!r} is {size_bytes} bytes and the read limit is {self._max_bytes}; it "
                    "is refused whole rather than returned in part, because a partial read would "
                    "be recorded under the digest of the part",
                    record_detail=f"resolved to {target}",
                )
            raw = target.read_bytes()
        except OSError as exc:
            return _refuse_os_error(exc, shown=shown, target=target)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return ToolRefusal(
                Reason.NOT_UTF8,
                f"{shown!r} is {len(raw)} bytes that are not valid UTF-8 text; it is not returned "
                "decoded with replacement, because text that silently lost bytes reads like text "
                "that did not",
                status=ToolStatus.FAILED,
                record_detail=f"resolved to {target}",
            )
        return ToolOutput(content=text)


class _WriteFile:
    """``write_file``'s handler. Stateless: the write root travels on the context."""

    __slots__ = ()

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput | ToolRefusal:
        """Replace one file's contents, creating its parents inside the write root.

        Args:
            args: ``path`` (resolved by the executor, proven inside the write root) and
                ``content``.
            context: The invocation, for the write root the parents are created under.

        Returns:
            A one-line confirmation naming the workspace-relative path and the byte count, or a
            refusal. ``path_escape`` is returned when a parent directory turns out to be a symlink
            — see :func:`_make_parents` for why that check is here and not only in the executor.
        """
        target = Path(str(args["path"]))
        shown = _shown(target, context)
        content = str(args["content"])
        refusal = _make_parents(target, context, shown=shown)
        if refusal is not None:
            return refusal
        try:
            if target.is_symlink():
                return ToolRefusal(
                    Reason.PATH_ESCAPE,
                    f"{shown!r} is a symbolic link; this tool replaces files, and following a link "
                    "to write is how a contained path writes to an uncontained one",
                    record_detail=f"resolved to {target}",
                )
            written = target.write_text(content, encoding="utf-8")
        except OSError as exc:
            return _refuse_os_error(exc, shown=shown, target=target)
        return ToolOutput(
            content=f"Wrote {written} characters to {shown}.",
            structured={"path": shown, "characters_written": written},
        )


class _ListDir:
    """``list_dir``'s handler. Holds its entry cap and nothing else."""

    __slots__ = ("_max_entries",)

    def __init__(self, max_entries: int) -> None:
        """Bind the handler to its entry cap."""
        self._max_entries = max_entries

    def execute(self, args: Mapping[str, Any], context: ToolContext) -> ToolOutput | ToolRefusal:
        """List one directory, sorted by name, capped and labelled.

        Sorted because the order a model reads is part of what it will act on, and
        :meth:`pathlib.Path.iterdir` returns whatever order the filesystem holds — two runs of the
        same trajectory would otherwise differ for no reason anyone chose.

        Args:
            args: ``path``, already resolved by the executor and proven inside a readable root.
            context: The invocation, for rendering the path back to the model.

        Returns:
            One line per entry — ``dir  name/`` or ``file name (N bytes)`` — with a final line
            naming how many entries were omitted when the cap was reached, or a refusal.
        """
        target = Path(str(args["path"]))
        shown = _shown(target, context)
        try:
            if not target.is_dir():
                return ToolRefusal(
                    Reason.NOT_A_REGULAR_FILE if target.exists() else Reason.FILE_NOT_FOUND,
                    f"{shown!r} is not a directory"
                    if target.exists()
                    else f"nothing exists at {shown!r}",
                    status=ToolStatus.FAILED,
                    record_detail=f"resolved to {target}",
                )
            entries = sorted(target.iterdir(), key=lambda entry: entry.name)
        except OSError as exc:
            return _refuse_os_error(exc, shown=shown, target=target)
        lines = [_entry_line(entry) for entry in entries[: self._max_entries]]
        omitted = len(entries) - len(lines)
        if omitted:
            lines.append(f"… {omitted} more entries not listed (limit {self._max_entries}).")
        body = "\n".join(lines) if lines else "(empty)"
        return ToolOutput(
            content=f"{shown}:\n{body}",
            structured={
                "path": shown,
                "entries": len(entries),
                "listed": len(lines) - bool(omitted),
            },
        )


def _entry_line(entry: Path) -> str:
    """Render one directory entry, without following it and without raising on it.

    A dangling symlink, a socket, or an entry removed between the listing and the ``stat`` all
    render as ``other`` rather than propagating an error out of a listing, and a symlink is named
    as a symlink rather than as whatever it points at — a model told "file" about a link into
    another root has been told something the containment rules do not agree with.
    """
    try:
        if entry.is_symlink():
            return f"link {entry.name}"
        if entry.is_dir():
            return f"dir  {entry.name}/"
        if entry.is_file():
            return f"file {entry.name} ({entry.stat().st_size} bytes)"
    except OSError:
        return f"other {entry.name}"
    return f"other {entry.name}"


def _make_parents(target: Path, context: ToolContext, *, shown: str) -> ToolRefusal | None:
    """Create ``target``'s missing parent directories, inside the write root, one level at a time.

    The development plan's named failure mode for this phase is *"``write_file`` creating parents
    outside the root via a symlinked intermediate directory"*, and ``mkdir(parents=True)`` is
    exactly how that happens: it walks components the executor never resolved, and it follows a
    symlink it finds on the way without comment.

    So the walk is explicit. It starts at the resolved write root — the executor has already proven
    ``target`` is inside it — and descends one component at a time. A component that exists and is
    a **symbolic link** stops the walk with ``path_escape``, whatever it points at, because the
    executor's resolution answered a question about the components that existed *then* and this one
    exists now. A component that does not exist is created directly, and a directory this call just
    created cannot be a link to anywhere.

    What this does not close is the race itself: between the check on one level and the ``mkdir`` on
    the next, another process on the same machine may still swap a directory for a link. Closing
    that needs ``openat``/``O_NOFOLLOW`` walking, which needs ``os`` — and ``.importlinter`` gives
    this module ``pathlib`` and nothing else, deliberately, so that path handling stays where
    containment is. The window is narrowed to one component at a time and it is stated here rather
    than implied away.

    Args:
        target: The resolved file path whose parents are wanted.
        context: The invocation, for the write root the walk starts from.
        shown: The workspace-relative path, for the model.

    Returns:
        ``None`` when every parent exists or was created, or the refusal that stopped the walk.
    """
    try:
        root = fully_resolve(context.workspace.write_root)
        relative = target.parent.relative_to(root)
    except (OSError, ValueError, RuntimeError):
        # `target` is inside a *read* root, or the write root will not resolve. Either way this
        # call creates nothing: a read root is not writable, and the write below will refuse.
        return None
    current = root
    for part in relative.parts:
        current = current / part
        try:
            if current.is_symlink():
                return ToolRefusal(
                    Reason.PATH_ESCAPE,
                    f"a directory on the way to {shown!r} is a symbolic link; parents are created "
                    "inside the write root and never through a link out of it",
                    record_detail=f"symlinked component: {current}",
                )
            if not current.exists():
                current.mkdir()
            elif not current.is_dir():
                return ToolRefusal(
                    Reason.NOT_A_REGULAR_FILE,
                    f"a component on the way to {shown!r} exists and is not a directory",
                    status=ToolStatus.FAILED,
                    record_detail=f"blocking component: {current}",
                )
        except OSError as exc:
            return _refuse_os_error(exc, shown=shown, target=current)
    return None


def read_file_tool(*, max_bytes: int = DEFAULT_MAX_READ_BYTES) -> tuple[ToolSpec, ToolHandler]:
    """Build ``read_file``: read one UTF-8 text file from inside the invocation's readable roots.

    Args:
        max_bytes: The largest file this tool will load. See :data:`DEFAULT_MAX_READ_BYTES` for why
            exceeding it refuses rather than truncates.

    Returns:
        The ``(spec, handler)`` pair for ``registry.register(*read_file_tool())``.

    Raises:
        ValidationError: If ``max_bytes`` is not an ``int`` of at least :data:`MIN_READ_BYTES`. A
            cap is the caller's input, so a bad one is a caller bug and raises at startup.
    """
    cap = _require_cap("max_bytes", max_bytes, MIN_READ_BYTES)
    spec = ToolSpec(
        name="read_file",
        description=(
            "Read a UTF-8 text file from the workspace and return its contents. Paths are "
            "relative to the workspace root unless absolute, and a path outside the workspace is "
            f"refused. Files over {cap} bytes are refused rather than partly read, as are files "
            "that are not text."
        ),
        args_schema=_READ_SCHEMA,
        result_schema=None,
        risk_class=RiskClass.READ_ONLY,
        egress=EgressClass.NONE,
        path_args={"path": PathAccess.READ},
    )
    return spec, _ReadFile(cap)


def write_file_tool() -> tuple[ToolSpec, ToolHandler]:
    """Build ``write_file``: replace one file's contents inside the invocation's write root.

    Returns:
        The ``(spec, handler)`` pair for ``registry.register(*write_file_tool())``.
    """
    spec = ToolSpec(
        name="write_file",
        description=(
            "Write UTF-8 text to a file in the workspace, replacing it entirely — there is no "
            "append and no partial edit. Missing parent directories are created inside the "
            "workspace write root. Paths are relative to that root unless absolute, and a path "
            "outside it, or reached through a symbolic link, is refused."
        ),
        args_schema=_WRITE_SCHEMA,
        result_schema=None,
        risk_class=RiskClass.MUTATING,
        egress=EgressClass.NONE,
        path_args={"path": PathAccess.WRITE},
    )
    return spec, _WriteFile()


def list_dir_tool(*, max_entries: int = DEFAULT_MAX_LIST_ENTRIES) -> tuple[ToolSpec, ToolHandler]:
    """Build ``list_dir``: list one directory inside the invocation's readable roots.

    Args:
        max_entries: How many entries to return. A longer listing is cut at the cap with a final
            line naming how many were omitted.

    Returns:
        The ``(spec, handler)`` pair for ``registry.register(*list_dir_tool())``.

    Raises:
        ValidationError: If ``max_entries`` is not an ``int`` of at least :data:`MIN_LIST_ENTRIES`.
    """
    cap = _require_cap("max_entries", max_entries, MIN_LIST_ENTRIES)
    spec = ToolSpec(
        name="list_dir",
        description=(
            "List a directory in the workspace, sorted by name. Each line gives the kind (dir, "
            "file, link or other) and the name; symbolic links are named as links and not "
            f"followed. At most {cap} entries are returned, and the listing says how many were "
            "omitted."
        ),
        args_schema=_LIST_SCHEMA,
        result_schema=None,
        risk_class=RiskClass.READ_ONLY,
        egress=EgressClass.NONE,
        path_args={"path": PathAccess.READ},
    )
    return spec, _ListDir(cap)
