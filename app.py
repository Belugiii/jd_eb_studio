"""EB Studio · 桌面 GUI 版本。

基于 tkinter 的 AES-CBC eb 参数生成/解密工具，逻辑复用 eb_crypto 模块。
双击 exe 后直接弹出桌面窗口，无需浏览器。
"""

from __future__ import annotations

import json
import tkinter as tk
from tkinter import ttk

from eb_crypto import (
    DEFAULT_IV,
    DEFAULT_KEY_HEX,
    CryptoError,
    decrypt,
    encrypt,
    inspect,
)

WINDOW_TITLE = "EB Studio · 参数生成与解密"
WINDOW_SIZE = "1100x720"

SAMPLE_PAYLOADS = [
    ("空白 JSON", "{\n  \n}"),
    (
        "查询参数示例",
        json.dumps(
            {
                "expireDayType": 0,
                "operate": "201",
                "queryParam": "",
                "siteNo": "",
                "sortTax": "desc",
                "sortType": 1,
                "status": 0,
                "pageIndex": 1,
                "pageSize": 20,
            },
            ensure_ascii=False,
            indent=2,
        ),
    ),
    ("简单文本", "hello-eb"),
]

DEFAULT_PLAIN = json.dumps(
    {
        "expireDayType": 0,
        "operate": "201",
        "queryParam": "",
        "siteNo": "",
        "sortTax": "desc",
        "sortType": 1,
        "status": 0,
        "pageIndex": 1,
        "pageSize": 20,
    },
    ensure_ascii=False,
    indent=2,
)


class EBStudioApp:
    """EB Studio 主窗口。"""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(WINDOW_TITLE)
        self.root.geometry(WINDOW_SIZE)
        self.root.minsize(900, 600)

        # 配色（深色主题，贴近原 Web 版本风格）
        self.colors = {
            "bg": "#0d1117",
            "card": "#161b22",
            "card_alt": "#1f2530",
            "border": "#30363d",
            "fg": "#e6edf3",
            "muted": "#8b949e",
            "accent": "#58a6ff",
            "accent_text": "#0d1117",
            "success": "#3fb950",
            "error": "#f85149",
            "input_bg": "#010409",
        }

        self.root.configure(bg=self.colors["bg"])

        # 状态字段
        self.key_var = tk.StringVar(value=DEFAULT_KEY_HEX)
        self.iv_var = tk.StringVar(value=DEFAULT_IV.decode("ascii"))
        self.pretty_var = tk.StringVar(value="0")
        self.status_var = tk.StringVar(value="就绪")

        self._build_layout()
        self.plain_text.insert("1.0", DEFAULT_PLAIN)

    # ---------------- 布局 ----------------
    def _build_layout(self) -> None:
        # 顶部标题栏
        header = tk.Frame(self.root, bg=self.colors["bg"])
        header.pack(fill="x", padx=16, pady=(12, 4))

        tk.Label(
            header,
            text="EB",
            bg=self.colors["bg"],
            fg=self.colors["accent"],
            font=("Segoe UI", 16, "bold"),
        ).pack(side="left", padx=(0, 8))

        title_box = tk.Frame(header, bg=self.colors["bg"])
        title_box.pack(side="left")
        tk.Label(
            title_box,
            text="EB Studio",
            bg=self.colors["bg"],
            fg=self.colors["fg"],
            font=("Segoe UI", 13, "bold"),
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text="对照 JDUtils.java 的 AES-CBC 可视化工具",
            bg=self.colors["bg"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w")

        meta = tk.Frame(header, bg=self.colors["bg"])
        meta.pack(side="right")
        for label in ("AES/CBC/PKCS5Padding", f"IV {self.iv_var.get()}"):
            tk.Label(
                meta,
                text=label,
                bg=self.colors["card"],
                fg=self.colors["muted"],
                padx=8,
                pady=2,
                relief="flat",
                font=("Segoe UI", 9),
            ).pack(side="left", padx=4)

        # 算法参数区
        self._build_settings()

        # 工作区（生成 + 解密）
        workspace = tk.Frame(self.root, bg=self.colors["bg"])
        workspace.pack(fill="both", expand=True, padx=16, pady=8)
        workspace.columnconfigure(0, weight=1, uniform="pane")
        workspace.columnconfigure(1, weight=1, uniform="pane")
        workspace.rowconfigure(0, weight=1)

        self._build_encrypt_pane(workspace, 0, 0)
        self._build_decrypt_pane(workspace, 0, 1)

        # 运行信息
        self._build_insight()

        # 状态栏
        status_bar = tk.Frame(self.root, bg=self.colors["card_alt"], height=24)
        status_bar.pack(fill="x", side="bottom")
        tk.Label(
            status_bar,
            textvariable=self.status_var,
            bg=self.colors["card_alt"],
            fg=self.colors["muted"],
            anchor="w",
            padx=10,
            pady=2,
            font=("Segoe UI", 9),
        ).pack(fill="x")

    def _build_settings(self) -> None:
        frame = tk.Frame(
            self.root,
            bg=self.colors["card"],
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        )
        frame.pack(fill="x", padx=16, pady=6)

        head = tk.Frame(frame, bg=self.colors["card"])
        head.pack(fill="x", padx=12, pady=(8, 4))
        tk.Label(
            head,
            text="算法参数",
            bg=self.colors["card"],
            fg=self.colors["fg"],
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left")
        tk.Label(
            head,
            text="密钥为十六进制，默认与源码 pass 一致",
            bg=self.colors["card"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
        ).pack(side="left", padx=10)

        grid = tk.Frame(frame, bg=self.colors["card"])
        grid.pack(fill="x", padx=12, pady=(0, 10))
        grid.columnconfigure(1, weight=1)

        # AES Key
        tk.Label(
            grid,
            text="AES Key（hex）",
            bg=self.colors["card"],
            fg=self.colors["muted"],
            anchor="w",
            font=("Segoe UI", 9),
        ).grid(row=0, column=0, sticky="w", padx=(0, 10), pady=4)
        key_entry = tk.Entry(
            grid,
            textvariable=self.key_var,
            bg=self.colors["input_bg"],
            fg=self.colors["fg"],
            insertbackground=self.colors["fg"],
            relief="flat",
            font=("Consolas", 10),
            bd=0,
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["accent"],
        )
        key_entry.grid(row=0, column=1, sticky="ew", pady=4, ipady=4)

        # IV
        tk.Label(
            grid,
            text="IV",
            bg=self.colors["card"],
            fg=self.colors["muted"],
            anchor="w",
            font=("Segoe UI", 9),
        ).grid(row=0, column=2, sticky="w", padx=(20, 10), pady=4)
        iv_entry = tk.Entry(
            grid,
            textvariable=self.iv_var,
            state="readonly",
            bg=self.colors["input_bg"],
            fg=self.colors["muted"],
            relief="flat",
            font=("Consolas", 10),
            bd=0,
            highlightthickness=1,
            highlightbackground=self.colors["border"],
        )
        iv_entry.grid(row=0, column=3, sticky="ew", pady=4, ipady=4)

        # 输出模式
        tk.Label(
            grid,
            text="输出",
            bg=self.colors["card"],
            fg=self.colors["muted"],
            anchor="w",
            font=("Segoe UI", 9),
        ).grid(row=0, column=4, sticky="w", padx=(20, 10), pady=4)
        pretty_box = tk.OptionMenu(
            grid,
            self.pretty_var,
            "0",
            *["0", "1"],
        )
        pretty_box["menu"].delete(0, "end")
        pretty_box["menu"].add_command(
            label="原文加密", command=lambda: self.pretty_var.set("0")
        )
        pretty_box["menu"].add_command(
            label="JSON 压缩后再加密", command=lambda: self.pretty_var.set("1")
        )
        pretty_box.configure(
            bg=self.colors["input_bg"],
            fg=self.colors["fg"],
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            relief="flat",
            font=("Segoe UI", 9),
            bd=0,
        )
        pretty_box.grid(row=0, column=5, sticky="w", pady=4, ipadx=6, ipady=2)

    def _build_pane(self, parent: tk.Frame, row: int, col: int, title: str, hint: str):
        pane = tk.Frame(
            parent,
            bg=self.colors["card"],
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        )
        pane.grid(row=row, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 6 if col == 0 else 0))
        pane.rowconfigure(2, weight=1)
        pane.columnconfigure(0, weight=1)

        head = tk.Frame(pane, bg=self.colors["card"])
        head.grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 4))
        head.columnconfigure(0, weight=1)
        tk.Label(
            head,
            text=title,
            bg=self.colors["card"],
            fg=self.colors["fg"],
            font=("Segoe UI", 11, "bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            head,
            text=hint,
            bg=self.colors["card"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="e",
        ).grid(row=0, column=1, sticky="e")
        return pane

    def _build_encrypt_pane(self, parent: tk.Frame, row: int, col: int) -> None:
        pane = self._build_pane(parent, row, col, "生成 eb", "明文 → 大写十六进制密文")

        # 示例按钮行
        samples = tk.Frame(pane, bg=self.colors["card"])
        samples.grid(row=1, column=0, sticky="ew", padx=12, pady=2)
        for label, body in SAMPLE_PAYLOADS:
            btn = tk.Label(
                samples,
                text=label,
                bg=self.colors["card_alt"],
                fg=self.colors["muted"],
                padx=8,
                pady=2,
                cursor="hand2",
                font=("Segoe UI", 9),
            )
            btn.pack(side="left", padx=(0, 6))
            btn.bind("<Button-1>", lambda e, b=body: self._set_plain(b))

        # 明文输入
        self.plain_text = tk.Text(
            pane,
            bg=self.colors["input_bg"],
            fg=self.colors["fg"],
            insertbackground=self.colors["fg"],
            relief="flat",
            font=("Consolas", 10),
            wrap="none",
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["accent"],
        )
        self.plain_text.grid(row=2, column=0, sticky="nsew", padx=12, pady=4)

        # 操作按钮
        actions = tk.Frame(pane, bg=self.colors["card"])
        actions.grid(row=3, column=0, sticky="ew", padx=12, pady=(4, 4))
        self._button(actions, "生成 eb", primary=True, command=self.on_encrypt)
        self._button(actions, "复制密文", command=lambda: self._copy(self.cipher_output))
        self._button(actions, "送到解密", command=self._to_decrypt)

        # 密文输出
        self.cipher_output = tk.Text(
            pane,
            bg=self.colors["input_bg"],
            fg=self.colors["accent"],
            relief="flat",
            font=("Consolas", 10),
            wrap="word",
            height=4,
            highlightthickness=1,
            highlightbackground=self.colors["border"],
        )
        self.cipher_output.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 10))
        self.cipher_output.insert("1.0", "等待生成...")
        self.cipher_output.configure(state="disabled")

    def _build_decrypt_pane(self, parent: tk.Frame, row: int, col: int) -> None:
        pane = self._build_pane(parent, row, col, "解密 eb", "密文 → UTF-8 明文")

        # 占位行，保持与加密面板对齐
        spacer = tk.Frame(pane, bg=self.colors["card"], height=24)
        spacer.grid(row=1, column=0, sticky="ew", padx=12, pady=2)

        # 密文输入
        self.cipher_input = tk.Text(
            pane,
            bg=self.colors["input_bg"],
            fg=self.colors["fg"],
            insertbackground=self.colors["fg"],
            relief="flat",
            font=("Consolas", 10),
            wrap="none",
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["accent"],
        )
        self.cipher_input.grid(row=2, column=0, sticky="nsew", padx=12, pady=4)

        # 操作按钮
        actions = tk.Frame(pane, bg=self.colors["card"])
        actions.grid(row=3, column=0, sticky="ew", padx=12, pady=(4, 4))
        self._button(actions, "解密", primary=True, command=self.on_decrypt)
        self._button(actions, "复制明文", command=lambda: self._copy(self.plain_output))
        self._button(actions, "送到加密", command=self._to_encrypt)

        # 明文输出
        self.plain_output = tk.Text(
            pane,
            bg=self.colors["input_bg"],
            fg=self.colors["accent"],
            relief="flat",
            font=("Consolas", 10),
            wrap="word",
            height=4,
            highlightthickness=1,
            highlightbackground=self.colors["border"],
        )
        self.plain_output.grid(row=4, column=0, sticky="ew", padx=12, pady=(0, 10))
        self.plain_output.insert("1.0", "等待解密...")
        self.plain_output.configure(state="disabled")

    def _build_insight(self) -> None:
        frame = tk.Frame(
            self.root,
            bg=self.colors["card"],
            highlightbackground=self.colors["border"],
            highlightthickness=1,
        )
        frame.pack(fill="x", padx=16, pady=(0, 8))

        head = tk.Frame(frame, bg=self.colors["card"])
        head.pack(fill="x", padx=12, pady=(8, 4))
        tk.Label(
            head,
            text="运行信息",
            bg=self.colors["card"],
            fg=self.colors["fg"],
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left")
        self.stat_status = tk.Label(
            head,
            text="就绪",
            bg=self.colors["card"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
        )
        self.stat_status.pack(side="right")

        stats = tk.Frame(frame, bg=self.colors["card"])
        stats.pack(fill="x", padx=12, pady=(0, 8))
        for i in range(6):
            stats.columnconfigure(i, weight=1, uniform="stat")

        self.stat_labels: dict[str, tk.Label] = {}
        defaults = {
            "algorithm": ("算法", "AES/CBC/PK5"),
            "keyBits": ("密钥长度", "16 字节 / 128 bit"),
            "plainBytes": ("明文长度", "-"),
            "paddedBytes": ("填充后", "-"),
            "cipherBlocks": ("密文块数", "-"),
            "time": ("最近操作", "-"),
        }
        for i, (key, (label, default)) in enumerate(defaults.items()):
            cell = tk.Frame(stats, bg=self.colors["card_alt"])
            cell.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 4, 4 if i == 5 else 0))
            tk.Label(
                cell,
                text=label,
                bg=self.colors["card_alt"],
                fg=self.colors["muted"],
                font=("Segoe UI", 9),
                padx=8,
                anchor="w",
            ).pack(fill="x", pady=(4, 0))
            value = tk.Label(
                cell,
                text=default,
                bg=self.colors["card_alt"],
                fg=self.colors["fg"],
                font=("Segoe UI", 10, "bold"),
                padx=8,
                anchor="w",
            )
            value.pack(fill="x", pady=(0, 4))
            self.stat_labels[key] = value

        tk.Label(
            frame,
            text="加密流程：UTF-8 明文 → PKCS5 填充 → AES-CBC → 大写 hex。解密流程相反。",
            bg=self.colors["card"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            padx=12,
        ).pack(fill="x", pady=(0, 8))

    # ---------------- 控件工厂 ----------------
    def _button(
        self,
        parent: tk.Frame,
        text: str,
        *,
        primary: bool = False,
        command=None,
    ) -> tk.Button:
        if primary:
            bg = self.colors["accent"]
            fg = self.colors["accent_text"]
            active_bg = self.colors["accent"]
        else:
            bg = self.colors["card_alt"]
            fg = self.colors["fg"]
            active_bg = self.colors["border"]
        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground=fg,
            relief="flat",
            bd=0,
            padx=12,
            pady=4,
            cursor="hand2",
            font=("Segoe UI", 9),
        )
        btn.pack(side="left", padx=(0, 6))
        return btn

    # ---------------- 业务逻辑 ----------------
    def _current_key(self) -> str:
        return self.key_var.get().strip() or DEFAULT_KEY_HEX

    def _set_plain(self, body: str) -> None:
        self.plain_text.delete("1.0", "end")
        self.plain_text.insert("1.0", body)

    def _set_status(self, text: str, *, ok: bool = True) -> None:
        color = self.colors["success"] if ok else self.colors["error"]
        self.status_var.set(text)
        self.stat_status.configure(text=text, fg=color)

    def _set_output(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _copy(self, widget: tk.Text) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(widget.get("1.0", "end-1c"))
        self._set_status("已复制")

    def _apply_meta(self, meta: dict, time: str | None) -> None:
        if not meta:
            return
        self.stat_labels["algorithm"].configure(
            text=meta.get("algorithm", "AES/CBC/PK5")
        )
        self.stat_labels["keyBits"].configure(
            text=f"{meta.get('keyBytes', 16)} 字节 / {meta.get('keyBits', 128)} bit"
        )
        plain_bytes = meta.get("plainBytes")
        self.stat_labels["plainBytes"].configure(
            text=f"{plain_bytes} B" if plain_bytes is not None else "-"
        )
        padded_bytes = meta.get("paddedBytes")
        self.stat_labels["paddedBytes"].configure(
            text=f"{padded_bytes} B" if padded_bytes is not None else "-"
        )
        blocks = meta.get("cipherBlocks")
        if blocks is None and meta.get("cipherBytes"):
            blocks = meta["cipherBytes"] // 16
        self.stat_labels["cipherBlocks"].configure(
            text=str(blocks) if blocks is not None else "-"
        )
        self.stat_labels["time"].configure(text=time or "-")

    def on_encrypt(self) -> None:
        self._set_status("正在加密...")
        plaintext = self.plain_text.get("1.0", "end-1c")
        key = self._current_key()
        text = plaintext
        if self.pretty_var.get() == "1":
            try:
                text = json.dumps(
                    json.loads(text),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            except json.JSONDecodeError:
                pass
        try:
            cipher = encrypt(text, key)
            self._set_output(self.cipher_output, cipher)
            self._apply_meta(inspect(text, cipher, key), None)
            self._set_status("加密成功")
        except CryptoError as exc:
            self._set_output(self.cipher_output, str(exc))
            self._set_status("加密失败", ok=False)

    def on_decrypt(self) -> None:
        self._set_status("正在解密...")
        cipher_text = self.cipher_input.get("1.0", "end-1c")
        key = self._current_key()
        try:
            plain = decrypt(cipher_text, key)
            pretty = plain
            try:
                pretty = json.dumps(json.loads(plain), ensure_ascii=False, indent=2)
            except json.JSONDecodeError:
                pretty = plain
            self._set_output(self.plain_output, pretty)
            self._apply_meta(inspect(plain, cipher_text, key), None)
            self._set_status("解密成功")
        except CryptoError as exc:
            self._set_output(self.plain_output, str(exc))
            self._set_status("解密失败", ok=False)

    def _to_decrypt(self) -> None:
        text = self.cipher_output.get("1.0", "end-1c")
        if text and text != "等待生成...":
            self.cipher_input.delete("1.0", "end")
            self.cipher_input.insert("1.0", text)

    def _to_encrypt(self) -> None:
        text = self.plain_output.get("1.0", "end-1c")
        if text and text != "等待解密...":
            self.plain_text.delete("1.0", "end")
            self.plain_text.insert("1.0", text)


def main() -> None:
    root = tk.Tk()
    # 让 ttk 主题接近深色
    try:
        style = ttk.Style(root)
        style.theme_use("clam")
    except tk.TclError:
        pass
    EBStudioApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
