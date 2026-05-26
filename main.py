from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


APP_TITLE = "OnePass 密码管理器"
VAULT_FILE = Path(__file__).resolve().with_name("vault.enc")
MASTER_PASSWORD_PATTERN = re.compile(r"^\d{6,16}$")
FIELDS = ["网站", "用户名", "密码", "邮箱", "电话", "备注"]
LIST_COLUMNS = ["网站", "用户名", "密码", "邮箱", "电话"]
PASSWORD_REVEAL_MS = 8000
STATUS_CLEAR_MS = 5000
AUTO_SAVE_DEBOUNCE_MS = 800
IDLE_LOCK_MS = 5 * 60 * 1000
IDLE_ACTIVITY_EVENTS = (
    "<Any-KeyPress>",
    "<Any-ButtonPress>",
    "<MouseWheel>",
    "<Motion>",
    "<FocusIn>",
)


class VaultError(Exception):
    pass


def double_md5(text: str) -> str:
    first_hash = hashlib.md5(text.encode("utf-8")).hexdigest()
    return hashlib.md5(first_hash.encode("utf-8")).hexdigest()


def build_export_payload(records: list[dict[str, str]]) -> dict[str, object]:
    return {
        "version": 1,
        "records": [VaultStorage._normalize_record(record) for record in records],
    }


def parse_import_payload(payload: object) -> list[dict[str, str]]:
    if isinstance(payload, dict):
        payload = payload.get("records")

    if not isinstance(payload, list):
        raise VaultError("导入文件格式无效，必须是记录数组或包含 records 字段。")

    return [VaultStorage._normalize_record(record) for record in payload]


class VaultStorage:
    def __init__(self, vault_path: Path) -> None:
        self.vault_path = vault_path

    def exists(self) -> bool:
        return self.vault_path.exists()

    def load_records(self, master_password: str) -> list[dict[str, str]]:
        encrypted_bytes = self.vault_path.read_bytes()
        decrypted_bytes = self._run_openssl(
            encrypted_bytes,
            master_password,
            decrypt=True,
        )

        try:
            data = json.loads(decrypted_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise VaultError("主密码错误，或密码库文件已损坏。") from exc

        records = data.get("records")
        if not isinstance(records, list):
            raise VaultError("密码库格式无效。")

        return [self._normalize_record(record) for record in records]

    def save_records(self, master_password: str, records: list[dict[str, str]]) -> None:
        normalized_records = [self._normalize_record(record) for record in records]
        payload = json.dumps(
            {"version": 1, "records": normalized_records},
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        encrypted_bytes = self._run_openssl(payload, master_password, decrypt=False)
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.vault_path.write_bytes(encrypted_bytes)
        try:
            self.vault_path.chmod(0o600)
        except OSError:
            pass

    @staticmethod
    def _normalize_record(record: dict[str, str]) -> dict[str, str]:
        if not isinstance(record, dict):
            raise VaultError("检测到无效的密码记录。")

        normalized: dict[str, str] = {}
        for field in FIELDS:
            value = record.get(field, "")
            if value is None:
                value = ""
            value = str(value)
            if field not in {"密码", "备注"}:
                value = value.strip()
            normalized[field] = value
        return normalized

    @staticmethod
    def _run_openssl(payload: bytes, master_password: str, decrypt: bool) -> bytes:
        command = [
            "openssl",
            "enc",
            "-aes-256-cbc",
            "-md",
            "sha256",
            "-pbkdf2",
            "-pass",
            "env:ONEPASS_MASTER_PASSWORD",
        ]
        if decrypt:
            command.insert(2, "-d")

        env = os.environ.copy()
        env["ONEPASS_MASTER_PASSWORD"] = double_md5(master_password)

        try:
            result = subprocess.run(
                command,
                input=payload,
                capture_output=True,
                check=False,
                env=env,
            )
        except FileNotFoundError as exc:
            raise VaultError("系统缺少 openssl，无法使用 AES 加密。") from exc

        if result.returncode != 0:
            if decrypt:
                raise VaultError("主密码错误，或密码库文件已损坏。")
            stderr_text = result.stderr.decode("utf-8", errors="ignore").strip()
            raise VaultError(f"AES 加密失败：{stderr_text or '未知错误'}")

        return result.stdout


class OnePassApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1080x640")
        self.root.minsize(920, 560)

        self.storage = VaultStorage(VAULT_FILE)
        self.master_password: str | None = None
        self.records: list[dict[str, str]] = []
        self.selected_index: int | None = None
        self.tree: ttk.Treeview | None = None
        self.search_var: tk.StringVar | None = None
        self.status_var: tk.StringVar | None = None
        self.count_var: tk.StringVar | None = None
        self.status_clear_job: str | None = None
        self.idle_lock_job: str | None = None
        self.idle_lock_enabled = False
        self.auth_notice: str | None = None
        self.tree_menu: tk.Menu | None = None
        self.context_menu_index: int | None = None
        self.context_menu_column: str | None = None

        self._build_auth_screen()

    def _build_auth_screen(self, notice: str | None = None) -> None:
        self.master_password = None
        self.records = []
        self.selected_index = None
        self.auth_notice = notice
        self._disable_idle_lock()
        self._clear_root()

        container = ttk.Frame(self.root, padding=24)
        container.pack(fill="both", expand=True)

        card = ttk.LabelFrame(container, text="身份验证", padding=24)
        card.place(relx=0.5, rely=0.5, anchor="center", width=420, height=300)

        is_first_run = not self.storage.exists()
        title_text = "首次使用，请设置 6-16 位数字主密码" if is_first_run else "请输入 6-16 位数字主密码"
        ttk.Label(card, text=title_text, font=("PingFang SC", 14, "bold")).pack(anchor="w")
        ttk.Label(
            card,
            text="主密码会经过双重 MD5 处理后用于解锁本地 AES 加密密码库。",
            foreground="#555555",
        ).pack(anchor="w", pady=(8, 18))
        if not is_first_run and self.auth_notice:
            ttk.Label(card, text=self.auth_notice, foreground="#8a5a00").pack(anchor="w", pady=(0, 18))

        password_var = tk.StringVar()
        confirm_var = tk.StringVar()

        ttk.Label(card, text="主密码").pack(anchor="w")
        password_entry = ttk.Entry(card, textvariable=password_var, show="*", font=("Menlo", 14))
        password_entry.pack(fill="x", pady=(6, 12))
        password_entry.focus_set()

        confirm_entry: ttk.Entry | None = None
        if is_first_run:
            ttk.Label(card, text="确认主密码").pack(anchor="w")
            confirm_entry = ttk.Entry(card, textvariable=confirm_var, show="*", font=("Menlo", 14))
            confirm_entry.pack(fill="x", pady=(6, 18))
        else:
            ttk.Label(card, text="验证通过后才能进入密码库。", foreground="#555555").pack(
                anchor="w",
                pady=(0, 18),
            )

        def submit() -> None:
            password = password_var.get()
            if not MASTER_PASSWORD_PATTERN.fullmatch(password):
                messagebox.showerror("密码格式错误", "主密码必须是 6-16 位数字。")
                return

            if is_first_run:
                if password != confirm_var.get():
                    messagebox.showerror("密码不一致", "两次输入的主密码不一致。")
                    return
                try:
                    self.storage.save_records(password, [])
                except VaultError as exc:
                    messagebox.showerror("初始化失败", str(exc))
                    return
                self.master_password = password
                self.records = []
                self._build_main_screen()
                return

            try:
                records = self.storage.load_records(password)
            except VaultError as exc:
                messagebox.showerror("验证失败", str(exc))
                password_var.set("")
                password_entry.focus_set()
                return

            self.master_password = password
            self.records = records
            self._build_main_screen()

        button_row = ttk.Frame(card)
        button_row.pack(fill="x")
        ttk.Button(button_row, text="退出", command=self.root.destroy).pack(side="right")
        ttk.Button(button_row, text="进入", command=submit).pack(side="right", padx=(0, 8))

        self.root.bind("<Return>", lambda _event: submit())

        if confirm_entry is not None:
            confirm_entry.bind("<Return>", lambda _event: submit())

    def _build_main_screen(self) -> None:
        self._clear_root()
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_args: self._refresh_tree())
        self.status_var = tk.StringVar(value=self._default_status_text())
        self.count_var = tk.StringVar(value="显示 0 / 0 条")

        shell = ttk.Frame(self.root, padding=16)
        shell.pack(fill="both", expand=True)

        top_bar = ttk.Frame(shell)
        top_bar.pack(fill="x", pady=(0, 12))

        ttk.Label(top_bar, text=APP_TITLE, font=("PingFang SC", 16, "bold")).pack(side="left")
        ttk.Label(
            top_bar,
            text=f"已解锁，本地文件：{self.storage.vault_path.name}",
            foreground="#555555",
        ).pack(side="left", padx=(16, 0))

        action_bar = ttk.Frame(shell)
        action_bar.pack(fill="x", pady=(0, 12))

        ttk.Button(action_bar, text="新增记录", command=self._new_record).pack(side="left")
        ttk.Button(action_bar, text="删除记录", command=self._delete_record).pack(side="left", padx=8)
        ttk.Button(action_bar, text="复制密码", command=self._copy_password).pack(side="left")
        ttk.Button(action_bar, text="导入", command=self._import_records).pack(side="left")
        ttk.Button(action_bar, text="导出 JSON", command=self._export_json_records).pack(side="left", padx=(8, 0))
        ttk.Button(action_bar, text="导出 CSV", command=self._export_csv_records).pack(side="left", padx=8)
        ttk.Button(action_bar, text="修改主密码", command=self._change_master_password).pack(side="left")
        ttk.Button(action_bar, text="锁定", command=self._lock_application).pack(side="right")

        content = ttk.Frame(shell)
        content.pack(fill="both", expand=True)
        self._build_record_list(content)
        self._refresh_tree()
        self._enable_idle_lock()

        separator = ttk.Separator(shell, orient="horizontal")
        separator.pack(fill="x", pady=(12, 8))

        status_bar = ttk.Frame(shell)
        status_bar.pack(fill="x")
        ttk.Label(status_bar, textvariable=self.status_var, foreground="#555555").pack(side="left")
        ttk.Label(status_bar, textvariable=self.count_var, foreground="#555555").pack(side="right")

    def _build_record_list(self, parent: ttk.Frame) -> None:
        search_frame = ttk.Frame(parent)
        search_frame.pack(fill="x", pady=(0, 8))

        ttk.Label(search_frame, text="搜索").pack(side="left")
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(search_frame, text="清除", command=self._clear_search).pack(side="right")

        list_frame = ttk.LabelFrame(parent, text="密码列表", padding=12)
        list_frame.pack(fill="both", expand=True)

        table_frame = ttk.Frame(list_frame)
        table_frame.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(table_frame, columns=LIST_COLUMNS, show="headings", height=20)
        for column in LIST_COLUMNS:
            self.tree.heading(column, text=column)
            if column == "网站":
                width = 180
            elif column == "密码":
                width = 180
            else:
                width = 140
            self.tree.column(column, width=width, anchor="w")

        y_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        x_scrollbar = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar.grid(row=1, column=0, sticky="ew")

        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._open_selected_record)
        self.tree.bind("<Button-3>", self._show_tree_context_menu)
        self.tree.bind("<Button-2>", self._show_tree_context_menu)
        self.tree.bind("<Control-Button-1>", self._show_tree_context_menu)

        self.tree_menu = tk.Menu(self.root, tearoff=0)
        self.tree_menu.add_command(label="复制", command=self._copy_context_cell)

    def _refresh_tree(self, select_index: int | None = None) -> None:
        if self.tree is None:
            return

        self.tree.delete(*self.tree.get_children())
        visible_indexes: set[int] = set()
        for index, record in self._get_filtered_records():
            values = [record.get(column, "") for column in LIST_COLUMNS]
            self.tree.insert("", "end", iid=str(index), values=values)
            visible_indexes.add(index)

        if self.count_var is not None:
            self.count_var.set(f"显示 {len(visible_indexes)} / {len(self.records)} 条")

        target_index = self.selected_index if select_index is None else select_index
        if target_index is None or target_index not in visible_indexes:
            self.tree.selection_remove(self.tree.selection())
            return

        target_id = str(target_index)
        self.tree.selection_set(target_id)
        self.tree.focus(target_id)
        self.tree.see(target_id)

    def _new_record(self) -> None:
        self._open_record_dialog(record=None, index=None)

    def _delete_record(self) -> None:
        if self.selected_index is None:
            messagebox.showerror("未选择记录", "请先从左侧列表选择要删除的记录。")
            return

        if not self._run_modal_action(messagebox.askyesno, "确认删除", "确定删除当前记录吗？"):
            return

        deleted_index = self.selected_index
        deleted_record = self.records.pop(deleted_index)
        self.selected_index = None

        if not self._persist_records():
            self.records.insert(deleted_index, deleted_record)
            self.selected_index = deleted_index
            return

        self._refresh_tree()
        self._set_status("记录已删除。")

    def _persist_records(self) -> bool:
        if self.master_password is None:
            return False

        try:
            self.storage.save_records(self.master_password, self.records)
        except VaultError as exc:
            messagebox.showerror("保存失败", str(exc))
            return False
        return True

    def _on_tree_select(self, _event: tk.Event) -> None:
        if self.tree is None:
            return

        selection = self.tree.selection()
        if not selection:
            self.selected_index = None
            return

        self.selected_index = int(selection[0])
        self._set_status("已选中记录。")

    def _show_tree_context_menu(self, event: tk.Event) -> None:
        if self.tree is None or self.tree_menu is None:
            return

        row_id = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell" or not row_id or not column_id:
            return

        index = int(row_id)
        column_index = int(column_id.replace("#", "")) - 1
        if column_index < 0 or column_index >= len(LIST_COLUMNS):
            return

        self.context_menu_index = index
        self.context_menu_column = LIST_COLUMNS[column_index]
        self.selected_index = index
        self.tree.selection_set(row_id)
        self.tree.focus(row_id)
        self.tree_menu.tk_popup(event.x_root, event.y_root)
        self.tree_menu.grab_release()

    def _copy_context_cell(self) -> None:
        if self.context_menu_index is None or self.context_menu_column is None:
            return

        value = self._get_cell_value(self.context_menu_index, self.context_menu_column)
        if not value:
            messagebox.showerror("没有内容", "当前单元格没有可复制的内容。")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(value)
        self.root.update()
        self._set_status(f"已复制{self.context_menu_column}单元格内容。")

    def _open_selected_record(self, _event: tk.Event | None = None) -> None:
        if self.selected_index is None:
            return
        self._open_record_dialog(self.records[self.selected_index].copy(), self.selected_index)

    def _clear_root(self) -> None:
        self._cancel_status_clear()
        self._cancel_idle_lock()
        self.root.unbind("<Return>")
        for child in self.root.winfo_children():
            child.destroy()
        self.tree = None
        self.tree_menu = None
        self.context_menu_index = None
        self.context_menu_column = None

    def _get_filtered_records(self) -> list[tuple[int, dict[str, str]]]:
        term = ""
        if self.search_var is not None:
            term = self.search_var.get().strip().lower()

        if not term:
            return list(enumerate(self.records))

        keywords = [keyword for keyword in term.split() if keyword]
        matched_records: list[tuple[int, dict[str, str]]] = []
        for index, record in enumerate(self.records):
            haystack = " ".join(record.get(field, "") for field in FIELDS).lower()
            if all(keyword in haystack for keyword in keywords):
                matched_records.append((index, record))
        return matched_records

    def _clear_search(self) -> None:
        if self.search_var is None:
            return
        self.search_var.set("")
        self._set_status("已清除搜索条件。")

    def _copy_password(self) -> None:
        if self.selected_index is None:
            messagebox.showerror("未选择记录", "请先从列表中选择一条记录。")
            return

        password = self.records[self.selected_index].get("密码", "")
        if not password:
            messagebox.showerror("没有密码", "当前记录没有可复制的密码。")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()
        self._set_status("密码已复制到剪贴板。")

    def _get_cell_value(self, index: int, column: str) -> str:
        return self.records[index].get(column, "")

    def _open_record_dialog(self, record: dict[str, str] | None, index: int | None) -> None:
        if self.master_password is None:
            messagebox.showerror("未解锁", "请先输入主密码。")
            return

        resume_idle_lock = self.idle_lock_enabled
        if resume_idle_lock:
            self._disable_idle_lock()

        dialog = tk.Toplevel(self.root)
        dialog_title = "新增记录" if index is None else "记录详情"
        dialog.title(dialog_title)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.geometry("560x460")
        dialog.minsize(500, 420)

        form_frame = ttk.Frame(dialog, padding=20)
        form_frame.pack(fill="both", expand=True)

        ttk.Label(form_frame, text=dialog_title, font=("PingFang SC", 14, "bold")).grid(
            row=0,
            column=0,
            columnspan=3,
            sticky="w",
            pady=(0, 12),
        )

        form_widgets: dict[str, tk.Widget] = {}
        password_entry: ttk.Entry | None = None
        password_toggle_button: ttk.Button | None = None
        password_visible = False
        password_hide_job: str | None = None
        initial_record = VaultStorage._normalize_record(record or {})

        def cancel_password_hide() -> None:
            nonlocal password_hide_job
            if password_hide_job is None:
                return
            try:
                dialog.after_cancel(password_hide_job)
            except ValueError:
                pass
            password_hide_job = None

        def hide_password() -> None:
            nonlocal password_visible
            cancel_password_hide()
            password_visible = False
            if password_entry is not None and password_entry.winfo_exists():
                password_entry.configure(show="*")
            if password_toggle_button is not None and password_toggle_button.winfo_exists():
                password_toggle_button.configure(text="显示")

        def toggle_password() -> None:
            nonlocal password_visible, password_hide_job
            if password_entry is None or not password_entry.winfo_exists():
                return

            password_visible = not password_visible
            password_entry.configure(show="" if password_visible else "*")
            if password_toggle_button is not None and password_toggle_button.winfo_exists():
                password_toggle_button.configure(text="隐藏" if password_visible else "显示")

            if password_visible:
                cancel_password_hide()
                password_hide_job = dialog.after(PASSWORD_REVEAL_MS, hide_password)
            else:
                cancel_password_hide()

        for row_index, field in enumerate(FIELDS, start=1):
            ttk.Label(form_frame, text=field).grid(row=row_index, column=0, sticky="nw", pady=6)

            if field == "备注":
                text_widget = tk.Text(form_frame, height=8, wrap="word", font=("PingFang SC", 11))
                text_widget.grid(row=row_index, column=1, columnspan=2, sticky="nsew", pady=6)
                text_widget.insert("1.0", initial_record.get(field, ""))
                form_widgets[field] = text_widget
                continue

            if field == "密码":
                password_row = ttk.Frame(form_frame)
                password_row.grid(row=row_index, column=1, columnspan=2, sticky="ew", pady=6)
                entry = ttk.Entry(password_row, show="*", font=("Menlo", 12))
                entry.pack(side="left", fill="x", expand=True)
                entry.insert(0, initial_record.get(field, ""))
                toggle_button = ttk.Button(password_row, text="显示", width=6, command=toggle_password)
                toggle_button.pack(side="left", padx=(8, 0))
                form_widgets[field] = entry
                password_entry = entry
                password_toggle_button = toggle_button
                continue

            entry = ttk.Entry(form_frame, font=("PingFang SC", 11))
            entry.grid(row=row_index, column=1, columnspan=2, sticky="ew", pady=6)
            entry.insert(0, initial_record.get(field, ""))
            form_widgets[field] = entry

        form_frame.columnconfigure(1, weight=1)
        form_frame.rowconfigure(FIELDS.index("备注") + 1, weight=1)

        def collect_record() -> dict[str, str]:
            collected: dict[str, str] = {}
            for field in FIELDS:
                widget = form_widgets[field]
                if field == "备注":
                    assert isinstance(widget, tk.Text)
                    collected[field] = widget.get("1.0", "end").rstrip()
                    continue

                assert isinstance(widget, ttk.Entry)
                value = widget.get()
                if field != "密码":
                    value = value.strip()
                collected[field] = value
            return VaultStorage._normalize_record(collected)

        def close_dialog() -> None:
            cancel_password_hide()
            dialog.unbind("<Return>")
            dialog.unbind("<Escape>")
            dialog.destroy()
            if resume_idle_lock and self.master_password is not None:
                self._enable_idle_lock()

        def save_record() -> None:
            current_record = collect_record()
            if not any(current_record.values()):
                messagebox.showerror("内容为空", "请至少填写一项记录内容。", parent=dialog)
                return

            previous_records = [item.copy() for item in self.records]
            if index is None:
                self.records.append(current_record)
                new_index = len(self.records) - 1
            else:
                self.records[index] = current_record
                new_index = index

            if not self._persist_records():
                self.records = previous_records
                return

            self.selected_index = new_index
            self._refresh_tree(select_index=new_index)
            close_dialog()
            action_text = "新增" if index is None else "更新"
            self._set_status(f"记录已{action_text}并保存。")

        button_row = ttk.Frame(form_frame)
        button_row.grid(row=len(FIELDS) + 1, column=0, columnspan=3, sticky="e", pady=(16, 0))
        ttk.Button(button_row, text="取消", command=close_dialog).pack(side="right")
        ttk.Button(button_row, text="保存", command=save_record).pack(side="right", padx=(0, 8))

        dialog.bind("<Return>", lambda _event: save_record())
        dialog.bind("<Escape>", lambda _event: close_dialog())
        dialog.protocol("WM_DELETE_WINDOW", close_dialog)

        first_widget = form_widgets.get("网站")
        if isinstance(first_widget, ttk.Entry):
            first_widget.focus_set()

        self.root.wait_window(dialog)
        if resume_idle_lock and self.master_password is not None and not self.idle_lock_enabled:
            self._enable_idle_lock()

    def _change_master_password(self) -> None:
        if self.master_password is None:
            messagebox.showerror("未解锁", "请先输入主密码。")
            return

        resume_idle_lock = self.idle_lock_enabled
        if resume_idle_lock:
            self._disable_idle_lock()

        dialog = tk.Toplevel(self.root)
        dialog.title("修改主密码")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="修改主密码", font=("PingFang SC", 14, "bold")).grid(
            row=0,
            column=0,
            columnspan=2,
            sticky="w",
        )
        ttk.Label(
            frame,
            text="新主密码必须是 6-16 位数字，修改后会立即用新密码重新加密整个密码库。",
            foreground="#555555",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 16))

        current_var = tk.StringVar()
        new_var = tk.StringVar()
        confirm_var = tk.StringVar()

        ttk.Label(frame, text="当前主密码").grid(row=2, column=0, sticky="w", pady=6)
        current_entry = ttk.Entry(frame, textvariable=current_var, show="*", font=("Menlo", 12))
        current_entry.grid(row=2, column=1, sticky="ew", pady=6)

        ttk.Label(frame, text="新主密码").grid(row=3, column=0, sticky="w", pady=6)
        new_entry = ttk.Entry(frame, textvariable=new_var, show="*", font=("Menlo", 12))
        new_entry.grid(row=3, column=1, sticky="ew", pady=6)

        ttk.Label(frame, text="确认新主密码").grid(row=4, column=0, sticky="w", pady=6)
        confirm_entry = ttk.Entry(frame, textvariable=confirm_var, show="*", font=("Menlo", 12))
        confirm_entry.grid(row=4, column=1, sticky="ew", pady=6)

        frame.columnconfigure(1, weight=1)

        def submit() -> None:
            current_password = current_var.get()
            new_password = new_var.get()
            confirm_password = confirm_var.get()

            if current_password != self.master_password:
                messagebox.showerror("验证失败", "当前主密码不正确。", parent=dialog)
                current_var.set("")
                current_entry.focus_set()
                return

            if not MASTER_PASSWORD_PATTERN.fullmatch(new_password):
                messagebox.showerror("密码格式错误", "新主密码必须是 6-16 位数字。", parent=dialog)
                new_var.set("")
                confirm_var.set("")
                new_entry.focus_set()
                return

            if new_password != confirm_password:
                messagebox.showerror("密码不一致", "两次输入的新主密码不一致。", parent=dialog)
                confirm_var.set("")
                confirm_entry.focus_set()
                return

            old_password = self.master_password
            self.master_password = new_password
            try:
                self.storage.save_records(new_password, self.records)
            except VaultError as exc:
                self.master_password = old_password
                messagebox.showerror("修改失败", str(exc), parent=dialog)
                new_entry.focus_set()
                return

            dialog.unbind("<Return>")
            dialog.unbind("<Escape>")
            dialog.destroy()
            self._set_status("主密码已修改，密码库已使用新主密码重新加密。")
            self._run_modal_action(messagebox.showinfo, "修改成功", "主密码已更新。下次登录请使用新主密码。")

        def close_dialog() -> None:
            dialog.unbind("<Return>")
            dialog.unbind("<Escape>")
            dialog.destroy()
            if resume_idle_lock and self.master_password is not None:
                self._enable_idle_lock()

        button_row = ttk.Frame(frame)
        button_row.grid(row=5, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(button_row, text="取消", command=close_dialog).pack(side="right")
        ttk.Button(button_row, text="确认修改", command=submit).pack(side="right", padx=(0, 8))

        dialog.bind("<Return>", lambda _event: submit())
        dialog.bind("<Escape>", lambda _event: close_dialog())
        dialog.protocol("WM_DELETE_WINDOW", close_dialog)
        current_entry.focus_set()
        self.root.wait_window(dialog)
        if resume_idle_lock and self.master_password is not None and not self.idle_lock_enabled:
            self._enable_idle_lock()

    def _import_records(self) -> None:
        if self.master_password is None:
            messagebox.showerror("未解锁", "请先输入主密码。")
            return

        import_path = self._run_modal_action(
            filedialog.askopenfilename,
            title="导入密码记录",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
        )
        if not import_path:
            return

        try:
            raw_payload = json.loads(Path(import_path).read_text(encoding="utf-8"))
            imported_records = parse_import_payload(raw_payload)
        except (OSError, json.JSONDecodeError, VaultError) as exc:
            messagebox.showerror("导入失败", str(exc))
            return

        if not imported_records:
            messagebox.showerror("导入失败", "导入文件中没有可用记录。")
            return

        existing_records = [record.copy() for record in self.records]
        start_index = len(self.records)
        self.records.extend(imported_records)

        if not self._persist_records():
            self.records = existing_records
            return

        if self.search_var is not None and self.search_var.get():
            self.search_var.set("")

        self.selected_index = start_index
        self._refresh_tree(select_index=start_index)
        self._set_status(f"已导入 {len(imported_records)} 条记录。")

    def _export_json_records(self) -> None:
        if not self.records:
            messagebox.showerror("没有记录", "当前没有可导出的记录。")
            return

        if not self._run_modal_action(messagebox.askyesno, "导出确认", "导出文件为明文 JSON，请妥善保管。是否继续？"):
            return

        export_path = self._run_modal_action(
            filedialog.asksaveasfilename,
            title="导出密码记录",
            defaultextension=".json",
            initialfile="onepass-export.json",
            filetypes=[("JSON 文件", "*.json"), ("所有文件", "*.*")],
        )
        if not export_path:
            return

        try:
            export_payload = build_export_payload(self.records)
            Path(export_path).write_text(
                json.dumps(export_payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            Path(export_path).chmod(0o600)
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))
            return

        self._set_status(f"已导出 {len(self.records)} 条记录到 {Path(export_path).name}。")

    def _export_csv_records(self) -> None:
        if not self.records:
            messagebox.showerror("没有记录", "当前没有可导出的记录。")
            return

        if not self._run_modal_action(messagebox.askyesno, "导出确认", "导出文件为明文 CSV，请妥善保管。是否继续？"):
            return

        export_path = self._run_modal_action(
            filedialog.asksaveasfilename,
            title="导出密码记录 CSV",
            defaultextension=".csv",
            initialfile="onepass-export.csv",
            filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
        )
        if not export_path:
            return

        try:
            with Path(export_path).open("w", encoding="utf-8-sig", newline="") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=FIELDS)
                writer.writeheader()
                for record in self.records:
                    writer.writerow(VaultStorage._normalize_record(record))
            Path(export_path).chmod(0o600)
        except OSError as exc:
            messagebox.showerror("导出失败", str(exc))
            return

        self._set_status(f"已导出 {len(self.records)} 条记录到 {Path(export_path).name}。")

    def _default_status_text(self) -> str:
        return f"密码库已解锁，空闲 {IDLE_LOCK_MS // 60000} 分钟后自动锁定。"

    def _set_status(self, message: str, auto_clear_ms: int = STATUS_CLEAR_MS) -> None:
        if self.status_var is None:
            return

        self.status_var.set(message)
        self._cancel_status_clear()
        if auto_clear_ms > 0:
            self.status_clear_job = self.root.after(
                auto_clear_ms,
                lambda: self.status_var is not None and self.status_var.set(self._default_status_text()),
            )

    def _cancel_status_clear(self) -> None:
        if self.status_clear_job is None:
            return
        try:
            self.root.after_cancel(self.status_clear_job)
        except ValueError:
            pass
        self.status_clear_job = None

    def _run_modal_action(self, callback, *args, **kwargs):
        resume_idle_lock = self.idle_lock_enabled
        if resume_idle_lock:
            self._disable_idle_lock()
        try:
            return callback(*args, **kwargs)
        finally:
            if resume_idle_lock and self.master_password is not None:
                self._enable_idle_lock()

    def _enable_idle_lock(self) -> None:
        if self.idle_lock_enabled:
            self._reset_idle_timer()
            return

        for event_name in IDLE_ACTIVITY_EVENTS:
            self.root.bind(event_name, self._register_activity, add="+")

        self.idle_lock_enabled = True
        self._reset_idle_timer()

    def _disable_idle_lock(self) -> None:
        self._cancel_idle_lock()
        if not self.idle_lock_enabled:
            return

        for event_name in IDLE_ACTIVITY_EVENTS:
            self.root.unbind(event_name)

        self.idle_lock_enabled = False

    def _register_activity(self, _event: tk.Event | None = None) -> None:
        if not self.idle_lock_enabled:
            return
        self._reset_idle_timer()

    def _reset_idle_timer(self) -> None:
        if not self.idle_lock_enabled:
            return
        self._cancel_idle_lock()
        self.idle_lock_job = self.root.after(IDLE_LOCK_MS, self._auto_lock_application)

    def _cancel_idle_lock(self) -> None:
        if self.idle_lock_job is None:
            return
        try:
            self.root.after_cancel(self.idle_lock_job)
        except ValueError:
            pass
        self.idle_lock_job = None

    def _auto_lock_application(self) -> None:
        self.idle_lock_job = None
        self._lock_application(auto_locked=True)

    def _lock_application(self, auto_locked: bool = False) -> None:
        self._disable_idle_lock()
        try:
            self.root.clipboard_clear()
        except tk.TclError:
            pass

        notice = "由于空闲已自动锁定，请重新输入主密码。" if auto_locked else None
        self._build_auth_screen(notice=notice)


def main() -> None:
    root = tk.Tk()
    try:
        OnePassApp(root)
    except VaultError as exc:
        messagebox.showerror("启动失败", str(exc))
        root.destroy()
        return
    root.mainloop()


if __name__ == "__main__":
    main()
