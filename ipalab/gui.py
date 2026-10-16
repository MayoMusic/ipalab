"""Graphical front end for IPA Lab, built on CustomTkinter.

All presentation logic lives in :mod:`ipalab.presentation`; this module only
renders it. Archive inspection runs on a worker thread and results are handed
back to the UI thread through a queue, so a large archive never freezes the
window.
"""

from __future__ import annotations

import json
import queue
import threading
from tkinter import filedialog
from typing import List, Optional

try:
    import customtkinter as ctk
except ImportError as exc:  # pragma: no cover - depends on optional extra
    raise SystemExit(
        'The graphical interface needs an extra dependency.\n'
        'Install it with:  pip install "ipalab[gui]"'
    ) from exc

from . import __version__, presentation
from .inspector import ERROR, Report, find_ipa_files, inspect_ipa

_SEVERITY_COLOURS = {
    ERROR: "#e05252",
    "warning": "#f0a30a",
    "info": "#3b82f6",
}

_SEVERITY_TINTS = {
    ERROR: "#3a1f21",
    "warning": "#3a2f16",
    "info": "#16283f",
}

_PLACEHOLDER = "No archive loaded"
_MAX_SIDEBAR_ENTRIES = 300


class IPALabApp(ctk.CTk):
    """Main window."""

    def __init__(self) -> None:
        super().__init__()
        self.title(f"IPA Lab  {__version__}")
        self.geometry("1120x760")
        self.minsize(920, 600)

        self._reports: List[Report] = []
        self._active = 0
        self._results: queue.Queue = queue.Queue()

        self._build()
        self.after(120, self._drain_results)

        self.bind("<Control-o>", lambda _e: self._open_file())
        self.bind("<Control-s>", lambda _e: self._open_folder())

    # ---------------------------------------------------------------- layout

    def _build(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()
        self._build_status_bar()

    def _build_sidebar(self) -> None:
        bar = ctk.CTkFrame(self, width=250, corner_radius=0)
        bar.grid(row=0, column=0, sticky="nsw")
        bar.grid_propagate(False)

        ctk.CTkLabel(
            bar, text="IPA Lab", font=ctk.CTkFont(size=24, weight="bold")
        ).grid(row=0, column=0, padx=18, pady=(18, 0), sticky="w")
        ctk.CTkLabel(
            bar,
            text="read-only .ipa inspector",
            text_color=("gray35", "gray70"),
            font=ctk.CTkFont(size=12),
        ).grid(row=1, column=0, padx=18, pady=(2, 14), sticky="w")

        buttons = ctk.CTkFrame(bar, fg_color="transparent")
        buttons.grid(row=2, column=0, padx=14, pady=(0, 12), sticky="ew")

        ctk.CTkButton(buttons, text="Open IPA", command=self._open_file).pack(
            fill="x", pady=(0, 6)
        )
        ctk.CTkButton(
            buttons,
            text="Scan folder",
            command=self._open_folder,
            fg_color="transparent",
            border_width=1,
        ).pack(fill="x")

        ctk.CTkLabel(
            bar,
            text="ARCHIVES",
            text_color=("gray45", "gray65"),
            font=ctk.CTkFont(size=11, weight="bold"),
        ).grid(row=3, column=0, padx=18, pady=(0, 6), sticky="nw")

        self._list_box = ctk.CTkScrollableFrame(
            bar, fg_color="transparent", scrollbar_button_color=("gray70", "gray35")
        )
        self._list_box.grid(row=4, column=0, padx=8, pady=(0, 8), sticky="nsew")
        bar.grid_rowconfigure(4, weight=1)

        self._mode_switch = ctk.CTkSwitch(
            bar,
            text="Dark mode",
            command=self._toggle_mode,
            font=ctk.CTkFont(size=12),
        )
        self._mode_switch.grid(row=5, column=0, padx=18, pady=(4, 16), sticky="w")
        self._mode_switch.select()

    def _build_main(self) -> None:
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.grid(row=0, column=1, sticky="nsew", padx=14, pady=14)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(main, corner_radius=12)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.grid_columnconfigure(0, weight=1)

        self._title = ctk.CTkLabel(
            header, text=_PLACEHOLDER, anchor="w", font=ctk.CTkFont(size=21, weight="bold")
        )
        self._title.grid(row=0, column=0, padx=18, pady=(14, 0), sticky="ew")

        self._subtitle = ctk.CTkLabel(
            header,
            text="Open an archive, or scan a folder to audit many at once.",
            anchor="w",
            text_color=("gray35", "gray70"),
            font=ctk.CTkFont(size=13),
        )
        self._subtitle.grid(row=1, column=0, padx=18, pady=(2, 14), sticky="ew")

        self._tab_names = ("Overview", "Entitlements", "Binary", "Findings")
        strip = ctk.CTkFrame(main, fg_color="transparent")
        strip.grid(row=1, column=0, sticky="w", pady=(0, 8))

        self._tab_buttons = {}
        for column, name in enumerate(self._tab_names):
            button = ctk.CTkButton(
                strip,
                text=name,
                width=132,
                height=32,
                corner_radius=8,
                fg_color="transparent",
                hover_color=("gray85", "gray25"),
                font=ctk.CTkFont(size=13),
                command=lambda n=name: self._set_tab(n),
            )
            button.grid(row=0, column=column, padx=(0, 8))
            self._tab_buttons[name] = button

        self._content = ctk.CTkFrame(main, fg_color="transparent")
        self._content.grid(row=2, column=0, sticky="nsew")
        self._content.grid_rowconfigure(0, weight=1)
        self._content.grid_columnconfigure(0, weight=1)

        self._cards = {}
        for name in self._tab_names:
            container = ctk.CTkScrollableFrame(
                self._content,
                fg_color="transparent",
                scrollbar_button_color=("gray70", "gray35"),
            )
            container.grid(row=0, column=0, padx=2, pady=2, sticky="nsew")
            container.grid_columnconfigure(0, weight=1)
            card = ctk.CTkFrame(container, corner_radius=12)
            card.grid(row=0, column=0, padx=4, pady=4, sticky="new")
            card.grid_columnconfigure(1, weight=1)
            self._cards[name] = card

        self._active_tab = "Overview"
        self._set_tab("Overview")

    def _build_status_bar(self) -> None:
        bar = ctk.CTkFrame(self, height=38, corner_radius=0, fg_color=("gray88", "gray20"))
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(0, weight=1)

        self._status = ctk.CTkLabel(
            bar,
            text="Ready",
            anchor="w",
            text_color=("gray25", "gray75"),
            font=ctk.CTkFont(size=12),
        )
        self._status.grid(row=0, column=0, padx=18, pady=8, sticky="ew")

        ctk.CTkButton(
            bar,
            text="Copy JSON",
            width=110,
            height=26,
            command=self._copy_json,
            font=ctk.CTkFont(size=12),
        ).grid(row=0, column=1, padx=(0, 18), pady=6)

    # -------------------------------------------------------------- commands

    def _open_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Open IPA",
            filetypes=[("iOS application archive", "*.ipa"), ("All files", "*.*")],
        )
        if path:
            self._inspect([path])

    def _open_folder(self) -> None:
        folder = filedialog.askdirectory(title="Scan a folder for .ipa files")
        if not folder:
            return
        found = find_ipa_files(folder)
        if not found:
            self._set_status(f"No .ipa files found in {folder}")
            return
        self._inspect(found)

    def _inspect(self, paths: List[str]) -> None:
        self._set_status(f"Inspecting {len(paths)} archive(s)…")
        self._set_enabled(False)
        self._results.put(("job", paths, None))

    def _worker(self, paths: List[str]) -> None:
        """Runs off the UI thread so a large archive cannot freeze the window."""
        try:
            reports = [inspect_ipa(path) for path in paths]
        except Exception as exc:  # pragma: no cover - defensive
            self._results.put(("failed", str(exc), paths))
            return
        self._results.put(("done", reports, paths))

    def _copy_json(self) -> None:
        report = self._current()
        if report is None:
            self._set_status("Nothing to copy")
            return
        payload = json.dumps([r.as_dict() for r in self._reports], indent=2)
        self.clipboard_clear()
        self.clipboard_append(payload)
        self.update()
        self._set_status(f"Copied JSON for {len(self._reports)} archive(s) to the clipboard")

    def _toggle_mode(self) -> None:
        mode = "dark" if self._mode_switch.get() else "light"
        ctk.set_appearance_mode(mode)

    # ---------------------------------------------------------------- events

    def _drain_results(self) -> None:
        try:
            kind, payload, paths = self._results.get_nowait()
        except queue.Empty:
            return

        if kind == "job":
            threading.Thread(
                target=self._worker, args=(payload,), daemon=True
            ).start()
        elif kind == "done":
            self._set_enabled(True)
            self._show_reports(payload)
            self._set_status(f"Inspected {len(paths)} archive(s)")
        elif kind == "failed":
            self._set_enabled(True)
            self._set_status(f"Inspection failed: {payload}")

        self.after(120, self._drain_results)

    def _set_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for child in self.winfo_children():
            self._walk_state(child, state)

    @staticmethod
    def _walk_state(widget, state: str) -> None:
        try:
            if isinstance(widget, (ctk.CTkButton, ctk.CTkSwitch)):
                widget.configure(state=state)
        except Exception:
            pass
        for child in widget.winfo_children():
            IPALabApp._walk_state(child, state)

    # ---------------------------------------------------------------- render

    def _show_reports(self, reports: List[Report]) -> None:
        self._reports = reports
        self._active = 0
        self._rebuild_sidebar()
        self._render()

    def _rebuild_sidebar(self) -> None:
        for child in self._list_box.winfo_children():
            child.destroy()

        for index, report in enumerate(self._reports[:_MAX_SIDEBAR_ENTRIES]):
            name = report.path.replace("\\", "/").rsplit("/", 1)[-1]
            severity = report.worst_severity
            marker = {"error": "  ✕", "warning": "  !"}.get(severity, "")
            ctk.CTkButton(
                self._list_box,
                text=f"{name}{marker}",
                anchor="w",
                height=30,
                font=ctk.CTkFont(size=12),
                fg_color="transparent",
                hover_color=("gray85", "gray25"),
                text_color=(
                    _SEVERITY_COLOURS.get(severity, ("gray10", "gray90"))
                    if severity in ("error", "warning")
                    else ("gray10", "gray90")
                ),
                command=lambda i=index: self._select(i),
            ).pack(fill="x", pady=1, padx=2)

        if len(self._reports) > _MAX_SIDEBAR_ENTRIES:
            ctk.CTkLabel(
                self._list_box,
                text=f"…and {len(self._reports) - _MAX_SIDEBAR_ENTRIES} more",
                text_color=("gray45", "gray65"),
                font=ctk.CTkFont(size=11),
            ).pack(anchor="w", padx=10, pady=6)

    def _select(self, index: int) -> None:
        self._active = index
        self._render()

    def _current(self) -> Optional[Report]:
        if 0 <= self._active < len(self._reports):
            return self._reports[self._active]
        return None

    def _set_tab(self, name: str) -> None:
        self._active_tab = name
        for key, card in self._cards.items():
            container = card.master
            if key == name:
                container.grid()
            else:
                container.grid_remove()

        for key, button in self._tab_buttons.items():
            active = key == name
            button.configure(
                fg_color=("gray80", "gray25") if active else "transparent",
                text_color=("gray10", "gray95") if active else ("gray40", "gray70"),
            )

    def _render(self) -> None:
        report = self._current()
        if report is None:
            self._title.configure(text=_PLACEHOLDER)
            self._subtitle.configure(
                text="Open an archive, or scan a folder to audit many at once."
            )
            for card in self._cards.values():
                self._render_rows(card, [("Status", _PLACEHOLDER)])
            return

        self._title.configure(text=presentation.summary_line(report))
        counts = presentation.counts_by_severity(report)
        parts = [report.path]
        if counts["error"]:
            parts.append(f"{counts['error']} error(s)")
        if counts["warning"]:
            parts.append(f"{counts['warning']} warning(s)")
        if not report.issues:
            parts.append("no findings")
        self._subtitle.configure(text="   ".join(parts))

        self._render_rows(self._cards["Overview"], presentation.metadata_rows(report))
        self._render_rows(self._cards["Binary"], presentation.binary_rows(report))

        entitlements = presentation.entitlement_rows(report)
        self._render_rows(
            self._cards["Entitlements"],
            entitlements or [("Status", "No entitlements were found in this archive.")],
        )

        findings = presentation.ordered_findings(report)
        self._render_rows(
            self._cards["Findings"],
            [(code, f"[{severity}]  {message}") for severity, code, message in findings]
            or [("Status", "Nothing to report. This archive looks clean.")],
        )

    @staticmethod
    def _clear(widget) -> None:
        for child in widget.winfo_children():
            child.destroy()

    @staticmethod
    def _render_rows(parent, rows) -> None:
        IPALabApp._clear(parent)
        for index, (label, value) in enumerate(rows):
            ctk.CTkLabel(
                parent,
                text=label,
                anchor="w",
                width=190,
                justify="left",
                text_color=("gray35", "gray70"),
                font=ctk.CTkFont(size=13),
            ).grid(row=index, column=0, padx=(18, 12), pady=7, sticky="nw")
            ctk.CTkLabel(
                parent,
                text=value,
                anchor="w",
                justify="left",
                wraplength=620,
                font=ctk.CTkFont(size=13),
            ).grid(row=index, column=1, padx=(0, 18), pady=7, sticky="ew")

        parent.grid_columnconfigure(1, weight=1)


def main() -> int:
    """Launch the GUI."""
    ctk.set_appearance_mode("dark")
    app = IPALabApp()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
