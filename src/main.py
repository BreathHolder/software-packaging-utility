"""Software Packaging Utility Application."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from src.utils.package_info_creator import build_package_info_creator_frame
from src.utils.package_info_updater import build_package_info_updater_frame
from src.utils.settings import build_settings_frame
from src.ui_styles import apply_styles


class RibbonApp(tk.Tk):
    """Main application window with a left-hand ribbon and dynamic content."""

    def __init__(self) -> None:
        """Initialize the window, styles, and default page."""
        super().__init__()
        self.title("Software Packaging Utilities")
        self.geometry("1200x960")
        self.minsize(1000, 700)

        self._load_branding()
        self._nav_colors = apply_styles(self)

        self._current_page: ttk.Frame | None = None
        self._pages = {
            "package_info": build_package_info_creator_frame,
            "package_info_update": build_package_info_updater_frame,
            "settings": build_settings_frame,
        }
        self._nav_items: dict[str, dict[str, object]] = {}
        self._active_page_key: str | None = None

        self._build_layout()
        self._show_page("package_info")

    def _load_branding(self) -> None:
        """Load window and ribbon branding images."""
        repo_root = Path(__file__).resolve().parents[1]
        icon_path = repo_root / "images" / "SPU-Logo-Square-32.png"
        menu_logo_path = repo_root / "images" / "SPU-Logo-Square-128.png"

        if icon_path.exists():
            self._app_icon = tk.PhotoImage(file=str(icon_path))
            self.iconphoto(True, self._app_icon)

        if menu_logo_path.exists():
            self._menu_logo = tk.PhotoImage(file=str(menu_logo_path))
        else:
            self._menu_logo = None

    def _build_layout(self) -> None:
        """Assemble the ribbon, scrollable content canvas, and layout bindings."""
        container = ttk.Frame(self, style="App.TFrame")
        container.pack(fill=tk.BOTH, expand=True)

        ribbon = ttk.Frame(container, style="Ribbon.TFrame", width=240)
        ribbon.pack(side=tk.LEFT, fill=tk.Y)
        ribbon.pack_propagate(False)

        if self._menu_logo is not None:
            logo_label = ttk.Label(
                ribbon,
                image=self._menu_logo,
                style="RibbonTitle.TLabel",
                background="#1f2a36",
            )
            logo_label.pack(padx=20, pady=(20, 8), anchor="center")

        self._add_ribbon_tab(
            ribbon,
            key="package_info",
            label="Package Info File Creator",
            command=lambda: self._show_page("package_info"),
        )
        self._add_ribbon_tab(
            ribbon,
            key="package_info_update",
            label="Package Info File Updater",
            command=lambda: self._show_page("package_info_update"),
        )
        self._add_ribbon_tab(
            ribbon,
            key="settings",
            label="Settings",
            command=lambda: self._show_page("settings"),
        )

        content = ttk.Frame(container, style="Content.TFrame")
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(content, highlightthickness=0, background="#f7f3ee")
        scrollbar = ttk.Scrollbar(content, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._scrollable_frame = ttk.Frame(canvas, style="Content.TFrame")
        self._scroll_window = canvas.create_window(
            (0, 0),
            window=self._scrollable_frame,
            anchor="nw",
        )
        self._content_canvas = canvas

        def _on_frame_configure(_event) -> None:
            """Resize the scrollable region after content changes."""
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(event) -> None:
            """Keep the inner frame width aligned to the canvas."""
            canvas.itemconfigure(self._scroll_window, width=event.width)

        self._scrollable_frame.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)
        self._bind_mousewheel(canvas)

    def _add_ribbon_tab(self, parent: ttk.Frame, key: str, label: str, command) -> None:
        """Create a ribbon tab with rounded corners."""
        canvas = tk.Canvas(
            parent,
            height=48,
            highlightthickness=0,
            bd=0,
            bg=self._nav_colors["ribbon_bg"],
        )
        canvas.pack(fill=tk.X, padx=(16, 16), pady=0)
        self._nav_items[key] = {
            "canvas": canvas,
            "label": label,
            "command": command,
            "hover": False,
        }

        def _on_click(_event=None) -> None:
            """Activate the selected page on click."""
            command()

        def _on_enter(_event=None) -> None:
            """Mark hover state for the tab for visual feedback."""
            self._nav_items[key]["hover"] = True
            self._redraw_nav_item(key)

        def _on_leave(_event=None) -> None:
            """Clear hover state when the cursor leaves the tab."""
            self._nav_items[key]["hover"] = False
            self._redraw_nav_item(key)

        canvas.bind("<Button-1>", _on_click)
        canvas.bind("<Enter>", _on_enter)
        canvas.bind("<Leave>", _on_leave)
        canvas.bind("<Configure>", lambda _event: self._redraw_nav_item(key))

    def _show_page(self, page_key: str) -> None:
        """Swap the active content frame and reset scroll position."""
        if (
            self._current_page is not None
            and self._active_page_key is not None
            and page_key != self._active_page_key
            and getattr(self._current_page, "is_dirty", False)
        ):
            if not messagebox.askyesno(
                "Unsaved Changes",
                "You have unsaved changes. Switching tabs will discard them.\n\nContinue?",
            ):
                return
        if self._current_page is not None:
            self._current_page.destroy()
        builder = self._pages[page_key]
        self._current_page = builder(self._scrollable_frame)
        self._current_page.pack(fill=tk.BOTH, expand=True, padx=24, pady=24)
        self._content_canvas.yview_moveto(0)
        self._set_active_nav(page_key)

    def _set_active_nav(self, page_key: str) -> None:
        """Highlight the active ribbon item like a selected tab."""
        if self._active_page_key == page_key:
            return
        for key in self._nav_items:
            self._redraw_nav_item(key, active_key=page_key)
        self._active_page_key = page_key

    def _redraw_nav_item(self, key: str, active_key: str | None = None) -> None:
        """Redraw a ribbon tab based on active/hover state."""
        active_key = active_key or self._active_page_key
        item = self._nav_items[key]
        canvas: tk.Canvas = item["canvas"]  # type: ignore[assignment]
        label: str = item["label"]  # type: ignore[assignment]
        is_active = key == active_key
        is_hover = bool(item.get("hover"))

        if is_active:
            canvas.pack_configure(padx=(16, 0))
        else:
            canvas.pack_configure(padx=(16, 16))

        canvas.delete("all")
        width = max(canvas.winfo_width(), 1)
        height = max(canvas.winfo_height(), 1)
        pad = 0
        radius = min(16, (height - pad * 2) // 2)

        if is_active:
            fill = self._nav_colors["tab_active_bg"]
            outline = self._nav_colors["tab_active_border"]
            text_color = self._nav_colors["tab_active_fg"]
        else:
            fill = self._nav_colors["tab_hover_bg"] if is_hover else self._nav_colors["tab_bg"]
            outline = self._nav_colors["tab_border"]
            text_color = self._nav_colors["tab_fg"]

        self._draw_left_rounded_rect(
            canvas,
            pad,
            pad,
            width - pad,
            height - pad,
            radius,
            fill=fill,
            outline=outline,
        )
        canvas.create_text(
            16,
            height // 2,
            text=label,
            anchor="w",
            fill=text_color,
            font=("Segoe UI", 11, "bold"),
        )

    def _draw_left_rounded_rect(
        self,
        canvas: tk.Canvas,
        x1: int,
        y1: int,
        x2: int,
        y2: int,
        radius: int,
        **kwargs,
    ) -> None:
        """Draw a rounded rectangle on a canvas."""
        radius = max(0, radius)
        fill = kwargs.pop("fill", "")
        outline = kwargs.pop("outline", "")
        width = kwargs.pop("width", 1)
        if radius == 0:
            canvas.create_rectangle(x1, y1, x2, y2, fill=fill, outline=outline, width=width)
            return

        canvas.create_rectangle(x1 + radius, y1, x2, y2, fill=fill, outline="")
        canvas.create_rectangle(x1, y1 + radius, x1 + radius, y2 - radius, fill=fill, outline="")
        canvas.create_arc(
            x1,
            y1,
            x1 + radius * 2,
            y1 + radius * 2,
            start=90,
            extent=90,
            style=tk.PIESLICE,
            fill=fill,
            outline="",
        )
        canvas.create_arc(
            x1,
            y2 - radius * 2,
            x1 + radius * 2,
            y2,
            start=180,
            extent=90,
            style=tk.PIESLICE,
            fill=fill,
            outline="",
        )

        if not outline:
            return

        canvas.create_line(x1 + radius, y1, x2, y1, fill=outline, width=width)
        canvas.create_line(x2, y1, x2, y2, fill=outline, width=width)
        canvas.create_line(x2, y2, x1 + radius, y2, fill=outline, width=width)
        canvas.create_line(x1, y1 + radius, x1, y2 - radius, fill=outline, width=width)
        canvas.create_arc(
            x1,
            y1,
            x1 + radius * 2,
            y1 + radius * 2,
            start=90,
            extent=90,
            style=tk.ARC,
            outline=outline,
            width=width,
        )
        canvas.create_arc(
            x1,
            y2 - radius * 2,
            x1 + radius * 2,
            y2,
            start=180,
            extent=90,
            style=tk.ARC,
            outline=outline,
            width=width,
        )

    def _bind_mousewheel(self, canvas: tk.Canvas) -> None:
        """Enable mouse-wheel scrolling for the main content canvas."""
        def _on_mousewheel(event) -> None:
            """Scroll on Windows/macOS using MouseWheel delta."""
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _on_mousewheel_linux(event) -> None:
            """Scroll on Linux using button events."""
            if event.num == 4:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                canvas.yview_scroll(1, "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        canvas.bind_all("<Button-4>", _on_mousewheel_linux)
        canvas.bind_all("<Button-5>", _on_mousewheel_linux)


def main() -> None:
    """Launch the desktop application."""
    app = RibbonApp()
    app.mainloop()


if __name__ == "__main__":
    main()
