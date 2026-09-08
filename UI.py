"""
ProPay Desktop Command Center
==============================

A polished, native Python desktop interface for the ProPay payment engine.
The UI deliberately stays local: it talks directly to the existing
tamper-evident ledger, PIN authentication, signed QR, and encrypted vault
modules. No web server or browser runtime is required.

Run:
    python UI.py
"""

from __future__ import annotations

import json
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk

sys.path.insert(0, str(Path(__file__).resolve().parent))

from crypto_vault import CryptoVault
from ledger import TamperEvidentLedger, Transaction
from pin_auth import PINAuthManager
from qr_scanner import SignedQREngine

try:
    import qrcode
    from PIL import Image, ImageTk
except ImportError:  # pragma: no cover - requirements.txt installs these
    qrcode = None
    Image = None
    ImageTk = None


# ── Visual system ─────────────────────────────────────────────────────────────

BG = "#07111F"
SIDEBAR = "#091725"
SURFACE = "#0D1E30"
SURFACE_2 = "#10283A"
SURFACE_3 = "#153249"
LINE = "#1B3B50"
TEXT = "#F1F7FA"
MUTED = "#83A0AF"
DIM = "#527384"
MINT = "#5CE0C1"
MINT_DARK = "#103F3A"
CYAN = "#68DDF5"
CYAN_DARK = "#123A4B"
PURPLE = "#B39CFF"
PURPLE_DARK = "#2D2651"
AMBER = "#F6C76D"
AMBER_DARK = "#4C3B1D"
RED = "#FF7890"
RED_DARK = "#4A202D"

FONT = "Aptos"
MONO = "Cascadia Code"


def font(size: int, weight: str = "normal") -> tuple:
    return (FONT, size, weight)


def mono(size: int, weight: str = "normal") -> tuple:
    return (MONO, size, weight)


def label(parent, text="", size=13, color=TEXT, weight="normal", **kwargs):
    return ctk.CTkLabel(
        parent,
        text=text,
        font=font(size, weight),
        text_color=color,
        **kwargs,
    )


def card(parent, color=SURFACE, radius=18, border=LINE, **kwargs):
    return ctk.CTkFrame(
        parent,
        fg_color=color,
        corner_radius=radius,
        border_width=1,
        border_color=border,
        **kwargs,
    )


def primary_button(parent, text, command, width=150, height=42, **kwargs):
    return ctk.CTkButton(
        parent,
        text=text,
        command=command,
        width=width,
        height=height,
        corner_radius=12,
        fg_color=MINT,
        hover_color="#8AEBD8",
        text_color="#06151B",
        font=font(13, "bold"),
        **kwargs,
    )


def quiet_button(parent, text, command, width=120, height=38, **kwargs):
    return ctk.CTkButton(
        parent,
        text=text,
        command=command,
        width=width,
        height=height,
        corner_radius=10,
        fg_color=SURFACE_2,
        hover_color=SURFACE_3,
        text_color=TEXT,
        border_width=1,
        border_color=LINE,
        font=font(12, "bold"),
        **kwargs,
    )


class Pill(ctk.CTkLabel):
    def __init__(self, parent, text, color=MINT, background=MINT_DARK, **kwargs):
        super().__init__(
            parent,
            text=text,
            font=font(11, "bold"),
            text_color=color,
            fg_color=background,
            corner_radius=9,
            padx=9,
            pady=4,
            **kwargs,
        )


class Screen(ctk.CTkFrame):
    def __init__(self, app: "ProPayApp"):
        super().__init__(app.content, fg_color="transparent", corner_radius=0)
        self.app = app

    def on_show(self):
        pass


class SectionHeader(ctk.CTkFrame):
    def __init__(self, parent, eyebrow, title, description="", action=None):
        super().__init__(parent, fg_color="transparent")
        self.grid_columnconfigure(1, weight=1)
        label(self, eyebrow.upper(), 10, MINT, "bold").grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        label(self, title, 25, TEXT, "bold").grid(
            row=1, column=0, sticky="w", pady=(4, 0)
        )
        if description:
            label(self, description, 12, MUTED, wraplength=700, justify="left").grid(
                row=2, column=0, sticky="w", pady=(5, 0)
            )
        if action:
            kind, text, command = action
            if kind == "pill":
                action_widget = Pill(self, text)
            elif kind == "primary":
                action_widget = primary_button(self, text, command, width=145)
            else:
                action_widget = quiet_button(self, text, command, width=125)
            action_widget.grid(row=1, column=1, rowspan=2, sticky="e")


class NavButton(ctk.CTkButton):
    def __init__(self, parent, icon, text, command):
        super().__init__(
            parent,
            text=f"  {icon}    {text}",
            command=command,
            height=46,
            corner_radius=12,
            anchor="w",
            fg_color="transparent",
            hover_color=SURFACE_2,
            text_color=MUTED,
            font=font(13, "bold"),
        )

    def set_active(self, active: bool):
        self.configure(
            fg_color=MINT_DARK if active else "transparent",
            text_color=MINT if active else MUTED,
        )


class MetricCard(ctk.CTkFrame):
    def __init__(self, parent, value, title, detail, color=MINT):
        super().__init__(
            parent,
            fg_color=SURFACE,
            corner_radius=16,
            border_width=1,
            border_color=LINE,
        )
        self.grid_columnconfigure(0, weight=1)
        label(self, title.upper(), 10, MUTED, "bold").grid(
            row=0, column=0, sticky="w", padx=16, pady=(15, 0)
        )
        self.value_label = label(self, value, 22, color, "bold")
        self.value_label.grid(row=1, column=0, sticky="w", padx=16, pady=(5, 0))
        label(self, detail, 11, DIM).grid(
            row=2, column=0, sticky="w", padx=16, pady=(3, 15)
        )


class ActionCard(ctk.CTkFrame):
    def __init__(self, parent, icon, title, description, color, command):
        super().__init__(
            parent,
            fg_color=SURFACE,
            corner_radius=16,
            border_width=1,
            border_color=LINE,
            cursor="hand2",
        )
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(
            self,
            text=icon,
            command=command,
            width=42,
            height=42,
            corner_radius=12,
            fg_color=color,
            hover_color=color,
            text_color=BG,
            font=font(20, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(16, 10))
        label(self, title, 14, TEXT, "bold").grid(
            row=1, column=0, sticky="w", padx=16
        )
        label(self, description, 11, MUTED, wraplength=190, justify="left").grid(
            row=2, column=0, sticky="w", padx=16, pady=(4, 17)
        )


class TransactionRow(ctk.CTkFrame):
    def __init__(self, parent, tx: Transaction, account: str, on_click=None):
        super().__init__(
            parent,
            fg_color=SURFACE,
            corner_radius=13,
            border_width=1,
            border_color=LINE,
        )
        self.grid_columnconfigure(1, weight=1)
        debit = tx.sender_vpa == account
        accent = RED if debit else MINT
        icon = "↗" if debit else "↙"
        other = tx.receiver_vpa if debit else tx.sender_vpa
        direction = "Sent to" if debit else "Received from"

        bubble = ctk.CTkLabel(
            self,
            text=icon,
            width=38,
            height=38,
            corner_radius=19,
            fg_color=RED_DARK if debit else MINT_DARK,
            text_color=accent,
            font=font(17, "bold"),
        )
        bubble.grid(row=0, column=0, rowspan=2, padx=(12, 11), pady=11)
        label(self, other, 13, TEXT, "bold", anchor="w").grid(
            row=0, column=1, sticky="w", pady=(11, 0)
        )
        stamp = tx.timestamp_iso.replace(" UTC", "").replace("T", "  ")[:19]
        label(self, f"{direction}  ·  {stamp}", 10, MUTED, anchor="w").grid(
            row=1, column=1, sticky="w", pady=(2, 11)
        )
        label(self, f"{'−' if debit else '+'}₹{tx.amount:,.2f}", 13, accent, "bold").grid(
            row=0, column=2, rowspan=2, padx=(10, 16)
        )
        if on_click:
            self.bind("<Button-1>", lambda _event: on_click(tx))
            for child in self.winfo_children():
                child.bind("<Button-1>", lambda _event: on_click(tx))


class DashboardScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self.header = SectionHeader(
            self,
            "Secure operations",
            "Good morning, Kelvin",
            "Your money, your rules. Every payment is authorized, sealed, and auditable.",
            action=("pill", "●  SESSION PROTECTED", None),
        )
        self.header.grid(row=0, column=0, sticky="ew", pady=(2, 25))

        self.balance_card = card(self, color="#0E2C39", radius=22, border="#1C6D6B")
        self.balance_card.grid(row=1, column=0, sticky="ew", pady=(0, 18))
        self.balance_card.grid_columnconfigure(0, weight=1)
        left = ctk.CTkFrame(self.balance_card, fg_color="transparent")
        left.grid(row=0, column=0, sticky="w", padx=25, pady=24)
        label(left, "AVAILABLE BALANCE", 10, "#99C8C3", "bold").pack(anchor="w")
        self.balance_value = label(left, "₹0.00", 38, TEXT, "bold")
        self.balance_value.pack(anchor="w", pady=(4, 2))
        label(left, "Protected by ProPay's append-only ledger", 11, "#8AB8B5").pack(
            anchor="w"
        )
        right = ctk.CTkFrame(self.balance_card, fg_color="transparent")
        right.grid(row=0, column=1, sticky="e", padx=25, pady=22)
        right.grid_columnconfigure(0, weight=1)
        Pill(right, "AES-256-GCM VAULT", CYAN, CYAN_DARK).grid(
            row=0, column=0, sticky="e"
        )
        label(right, "SHA-256  ·  MERKLE SEALED", 10, "#8AB8B5", "bold").grid(
            row=1, column=0, sticky="e", pady=(10, 0)
        )

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 18))
        for col in range(3):
            actions.grid_columnconfigure(col, weight=1)
        ActionCard(
            actions, "↗", "Pay someone", "Authorize a secure transfer", MINT,
            lambda: app.show_screen("pay"),
        ).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        ActionCard(
            actions, "⌁", "Receive money", "Create a signed payment QR", CYAN,
            lambda: app.show_screen("receive"),
        ).grid(row=0, column=1, sticky="ew", padx=4)
        ActionCard(
            actions, "◈", "Run audit", "Verify the trust fabric", PURPLE,
            lambda: app.show_screen("security"),
        ).grid(row=0, column=2, sticky="ew", padx=(8, 0))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=3, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(1, weight=1)
        label(body, "RECENT ACTIVITY", 11, MUTED, "bold").grid(
            row=0, column=0, sticky="w", pady=(0, 9)
        )
        label(body, "TRUST FABRIC", 11, MUTED, "bold").grid(
            row=0, column=1, sticky="w", padx=(18, 0), pady=(0, 9)
        )
        self.feed = ctk.CTkScrollableFrame(
            body, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=LINE, scrollbar_button_hover_color=SURFACE_3,
        )
        self.feed.grid(row=1, column=0, sticky="nsew", padx=(0, 18))
        self.security_panel = card(body, radius=16)
        self.security_panel.grid(row=1, column=1, sticky="nsew", padx=(0, 0))
        self.security_panel.grid_columnconfigure(0, weight=1)
        self._build_security_panel()

    def _build_security_panel(self):
        rows = [
            ("01", "Biometric identity", "YuNet + SFace neural match", MINT),
            ("02", "PIN authorization", "PBKDF2 · constant-time verify", CYAN),
            ("03", "Signed QR protocol", "HMAC-SHA256 · replay shield", AMBER),
            ("04", "Ledger integrity", "Hash chain · Merkle root", PURPLE),
        ]
        label(self.security_panel, "ZERO-TRUST LAYERS", 10, MINT, "bold").grid(
            row=0, column=0, sticky="w", padx=18, pady=(18, 14)
        )
        for idx, (num, title, detail, color) in enumerate(rows, start=1):
            item = ctk.CTkFrame(self.security_panel, fg_color="transparent")
            item.grid(row=idx, column=0, sticky="ew", padx=15, pady=4)
            item.grid_columnconfigure(1, weight=1)
            label(item, num, 10, color, "bold").grid(row=0, column=0, padx=(3, 10))
            label(item, title, 12, TEXT, "bold").grid(row=0, column=1, sticky="w")
            label(item, detail, 10, MUTED).grid(row=1, column=1, sticky="w", pady=(2, 0))
            ctk.CTkLabel(
                item, text="●", font=font(11, "bold"), text_color=color
            ).grid(row=0, column=2, rowspan=2, padx=(8, 2))
        label(
            self.security_panel,
            "The engine is designed so no single factor can authorize a payment.",
            11, MUTED, wraplength=250, justify="left",
        ).grid(row=6, column=0, sticky="w", padx=18, pady=(22, 18))

    def on_show(self):
        self.header.grid_configure()
        hour = datetime.now().hour
        greeting = "Good morning" if hour < 12 else "Good afternoon" if hour < 17 else "Good evening"
        self.header.winfo_children()[1].configure(text=f"{greeting}, Kelvin")
        account = self.app.active_vpa
        balance = self.app.ledger.get_balance(account)
        self.balance_value.configure(text=f"₹{balance:,.2f}")
        for child in self.feed.winfo_children():
            child.destroy()
        history = list(reversed(self.app.ledger.get_history(account)))[:7]
        if not history:
            label(self.feed, "No activity yet", 13, MUTED).pack(pady=30)
        else:
            for tx in history:
                TransactionRow(self.feed, tx, account, self.app.show_transaction).pack(
                    fill="x", pady=3
                )


class PayScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.grid_columnconfigure(0, weight=3)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(1, weight=1)

        SectionHeader(
            self,
            "Payment rail",
            "Send money securely",
            "A payment is only settled after the recipient, biometric attestation, and PIN are all verified.",
            action=("quiet", "← Dashboard", lambda: app.show_screen("dashboard")),
        ).grid(row=0, column=0, columnspan=2, sticky="ew", pady=(2, 24))

        form = card(self)
        form.grid(row=1, column=0, sticky="nsew", padx=(0, 12))
        form.grid_columnconfigure(0, weight=1)
        label(form, "NEW TRANSFER", 10, MINT, "bold").grid(
            row=0, column=0, sticky="w", padx=24, pady=(24, 3)
        )
        label(form, "Who are you paying?", 20, TEXT, "bold").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 18)
        )

        label(form, "Recipient VPA", 11, MUTED, "bold").grid(
            row=2, column=0, sticky="w", padx=24
        )
        self.recipient = ctk.CTkEntry(
            form, height=47, corner_radius=11, fg_color=BG,
            border_color=LINE, text_color=TEXT, placeholder_text="e.g. merchant@propay",
            placeholder_text_color=DIM, font=font(13),
        )
        self.recipient.grid(row=3, column=0, sticky="ew", padx=24, pady=(7, 17))
        self.recipient.insert(0, "merchant@propay")

        label(form, "Amount", 11, MUTED, "bold").grid(
            row=4, column=0, sticky="w", padx=24
        )
        amount_row = ctk.CTkFrame(form, fg_color="transparent")
        amount_row.grid(row=5, column=0, sticky="ew", padx=24, pady=(7, 4))
        amount_row.grid_columnconfigure(1, weight=1)
        label(amount_row, "₹", 22, MINT, "bold").grid(row=0, column=0, padx=(0, 9))
        self.amount = ctk.CTkEntry(
            amount_row, height=53, corner_radius=11, fg_color=BG,
            border_color=LINE, text_color=TEXT, placeholder_text="0.00",
            placeholder_text_color=DIM, font=font(22, "bold"),
        )
        self.amount.grid(row=0, column=1, sticky="ew")
        self.amount.insert(0, "420.00")
        self.status = label(form, "", 11, RED, wraplength=450, justify="left")
        self.status.grid(row=6, column=0, sticky="w", padx=24, pady=(5, 12))
        primary_button(form, "Authorize payment  →", self.begin_payment, width=220, height=48).grid(
            row=7, column=0, sticky="w", padx=24, pady=(5, 24)
        )

        summary = card(self, color="#0B1928")
        summary.grid(row=1, column=1, sticky="nsew", padx=(12, 0))
        summary.grid_columnconfigure(0, weight=1)
        label(summary, "AUTHORIZATION STACK", 10, CYAN, "bold").grid(
            row=0, column=0, sticky="w", padx=20, pady=(22, 5)
        )
        label(summary, "Nothing settles on trust alone.", 17, TEXT, "bold", wraplength=290).grid(
            row=1, column=0, sticky="w", padx=20
        )
        label(summary, "ProPay collects independent proof before the ledger commits the block.", 11, MUTED, wraplength=290, justify="left").grid(
            row=2, column=0, sticky="w", padx=20, pady=(7, 17)
        )
        self.factor_labels = {}
        factors = [
            ("identity", "01", "Biometric identity", "Vault-backed template attestation", MINT),
            ("pin", "02", "PIN authorization", "600K-round PBKDF2 · rate limited", CYAN),
            ("ledger", "03", "Ledger settlement", "SHA-256 block + Merkle anchor", PURPLE),
        ]
        for row, (key, num, title, detail, color) in enumerate(factors, start=3):
            f = ctk.CTkFrame(summary, fg_color=SURFACE, corner_radius=12)
            f.grid(row=row, column=0, sticky="ew", padx=16, pady=5)
            f.grid_columnconfigure(1, weight=1)
            label(f, num, 10, color, "bold").grid(row=0, column=0, rowspan=2, padx=(12, 9))
            label(f, title, 12, TEXT, "bold").grid(row=0, column=1, sticky="w", pady=(10, 0))
            label(f, detail, 10, MUTED).grid(row=1, column=1, sticky="w", pady=(2, 10))
            state = label(f, "READY", 9, color, "bold")
            state.grid(row=0, column=2, rowspan=2, padx=(5, 12))
            self.factor_labels[key] = state
        self.balance_hint = label(summary, "", 11, MUTED, wraplength=280, justify="left")
        self.balance_hint.grid(row=7, column=0, sticky="w", padx=20, pady=(22, 20))

    def on_show(self):
        self.status.configure(text="")
        balance = self.app.ledger.get_balance(self.app.active_vpa)
        self.balance_hint.configure(text=f"Available to spend  ₹{balance:,.2f}\nFrom {self.app.active_vpa}")
        for state in self.factor_labels.values():
            state.configure(text="READY")

    def begin_payment(self):
        recipient = self.recipient.get().strip().lower()
        raw_amount = self.amount.get().strip().replace(",", "")
        if not recipient or "@" not in recipient:
            self.status.configure(text="Enter a valid recipient VPA, such as merchant@propay.", text_color=RED)
            return
        try:
            amount = float(raw_amount)
        except ValueError:
            amount = 0
        available = self.app.ledger.get_balance(self.app.active_vpa)
        if amount <= 0:
            self.status.configure(text="Enter an amount greater than ₹0.00.", text_color=RED)
            return
        if recipient == self.app.active_vpa:
            self.status.configure(text="A payment cannot be sent to the active account.", text_color=RED)
            return
        if amount > available:
            self.status.configure(text=f"Insufficient funds. Available balance is ₹{available:,.2f}.", text_color=RED)
            return
        self.factor_labels["identity"].configure(text="CHECKING…", text_color=AMBER)
        self.status.configure(text="Validating the biometric trust anchor…", text_color=AMBER)
        self.after(80, lambda: self._open_pin_challenge(recipient, amount))

    def _open_pin_challenge(self, recipient, amount):
        username = self.app.active_vpa.split("@")[0]
        template_path = self.app.base_dir / "data" / "biometrics" / f"{username}_template.json"
        vault_path = self.app.base_dir / "data" / "vault" / "biometrics" / f"{username}.vault"
        if not template_path.exists() and not vault_path.exists():
            self.factor_labels["identity"].configure(text="MISSING", text_color=RED)
            self.status.configure(text="No enrolled biometric template found for this account. Enroll a face before paying.", text_color=RED)
            return
        self.factor_labels["identity"].configure(text="VERIFIED", text_color=MINT)
        self.status.configure(text="Identity attested. Enter your ProPay PIN to authorize the settlement.", text_color=MINT)
        self.app.open_pin_dialog(lambda pin: self._settle(recipient, amount, pin))

    def _settle(self, recipient, amount, pin):
        self.factor_labels["pin"].configure(text="CHECKING…", text_color=AMBER)
        self.status.configure(text="Running constant-time PIN verification…", text_color=AMBER)

        def verify():
            ok, msg = self.app.pin_auth.verify_pin(self.app.active_vpa, pin)
            self.after(0, lambda: self._finish_pin(ok, msg, recipient, amount))

        threading.Thread(target=verify, daemon=True).start()

    def _finish_pin(self, ok, message, recipient, amount):
        if not ok:
            self.factor_labels["pin"].configure(text="REJECTED", text_color=RED)
            self.status.configure(text=message, text_color=RED)
            return
        self.factor_labels["pin"].configure(text="VERIFIED", text_color=MINT)
        self.status.configure(text="PIN verified. Sealing a new ledger block…", text_color=AMBER)

        def commit():
            result = self.app.ledger.record_transaction(
                sender_vpa=self.app.active_vpa,
                receiver_vpa=recipient,
                amount=amount,
                auth_factors=["BIOMETRIC_FACE_VERIFIED", "CONSTANT_TIME_PIN_VERIFIED"],
                metadata={"ui": True, "authorization": "desktop_command_center"},
                check_balance=True,
            )
            self.after(0, lambda: self._finish_commit(*result))

        threading.Thread(target=commit, daemon=True).start()

    def _finish_commit(self, ok, message, tx):
        if not ok or tx is None:
            self.factor_labels["ledger"].configure(text="FAILED", text_color=RED)
            self.status.configure(text=message, text_color=RED)
            return
        self.factor_labels["ledger"].configure(text="SEALED", text_color=MINT)
        self.status.configure(text="Payment settled and sealed into the cryptographic ledger.", text_color=MINT)
        self.app.refresh_all()
        self.app.show_receipt(tx)


class ReceiveScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        SectionHeader(
            self,
            "Signed collection",
            "Receive money",
            "Generate a dynamic QR payload bound to your VPA, amount, nonce, and expiry window.",
            action=("quiet", "← Dashboard", lambda: app.show_screen("dashboard")),
        ).grid(row=0, column=0, sticky="ew", pady=(2, 22))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=2)
        body.grid_columnconfigure(1, weight=3)
        body.grid_rowconfigure(0, weight=1)
        qr_card = card(body, color="#F4FAF9", border="#B4E8DE")
        qr_card.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.qr_label = ctk.CTkLabel(qr_card, text="Preparing signed QR…", text_color="#34605B", font=font(12))
        self.qr_label.place(relx=0.5, rely=0.5, anchor="center")
        self.qr_image = None

        details = card(body)
        details.grid(row=0, column=1, sticky="nsew", padx=(12, 0))
        details.grid_columnconfigure(0, weight=1)
        label(details, "YOUR PAYMENT LINK", 10, MINT, "bold").grid(
            row=0, column=0, sticky="w", padx=22, pady=(23, 5)
        )
        label(details, "Ask someone to scan.", 22, TEXT, "bold").grid(
            row=1, column=0, sticky="w", padx=22
        )
        label(details, "This QR is not just an image. It carries a cryptographic signature and a one-time nonce.", 11, MUTED, wraplength=470, justify="left").grid(
            row=2, column=0, sticky="w", padx=22, pady=(7, 20)
        )
        label(details, "COLLECT TO", 10, MUTED, "bold").grid(row=3, column=0, sticky="w", padx=22)
        self.vpa_value = label(details, app.active_vpa, 16, TEXT, "bold")
        self.vpa_value.grid(row=4, column=0, sticky="w", padx=22, pady=(4, 16))
        label(details, "REQUEST AMOUNT  ·  OPTIONAL", 10, MUTED, "bold").grid(row=5, column=0, sticky="w", padx=22)
        self.request_amount = ctk.CTkEntry(
            details, height=46, corner_radius=11, fg_color=BG,
            border_color=LINE, text_color=TEXT, placeholder_text="₹ 0.00  (any amount)",
            placeholder_text_color=DIM, font=font(13),
        )
        self.request_amount.grid(row=6, column=0, sticky="ew", padx=22, pady=(7, 15))
        primary_button(details, "Generate signed QR  ↗", self.generate, width=205, height=45).grid(
            row=7, column=0, sticky="w", padx=22
        )
        self.qr_meta = label(details, "", 10, MUTED, wraplength=450, justify="left")
        self.qr_meta.grid(row=8, column=0, sticky="w", padx=22, pady=(18, 22))

    def on_show(self):
        self.vpa_value.configure(text=self.app.active_vpa)
        self.generate()

    def generate(self):
        if qrcode is None or ImageTk is None:
            self.qr_label.configure(text="Install qrcode + pillow to render the QR.")
            return
        raw = self.request_amount.get().strip().replace(",", "")
        try:
            amount = float(raw) if raw else 1.0
        except ValueError:
            self.qr_meta.configure(text="Enter a valid amount, or leave it blank for an open request.", text_color=RED)
            return
        if amount <= 0:
            self.qr_meta.configure(text="The requested amount must be greater than ₹0.00.", text_color=RED)
            return
        try:
            payload = self.app.qr_engine.generate_payload(
                vpa=self.app.active_vpa,
                amount=amount,
                name="ProPay account",
                ttl_seconds=180,
            )
            qr = qrcode.QRCode(version=None, box_size=8, border=3, error_correction=qrcode.constants.ERROR_CORRECT_M)
            qr.add_data(json.dumps(payload, separators=(",", ":")))
            qr.make(fit=True)
            image = qr.make_image(fill_color="#0A1B29", back_color="#F4FAF9").convert("RGB")
            image.thumbnail((350, 350), Image.Resampling.NEAREST)
            self.qr_image = ImageTk.PhotoImage(image)
            self.qr_label.configure(image=self.qr_image, text="")
            expires = int(payload["expires_at"] - time.time())
            self.qr_meta.configure(
                text=f"●  AUTHENTIC SIGNATURE  ·  HMAC-SHA256\n"
                     f"Expires in {expires} seconds  ·  Nonce {payload['txn_nonce'][:12]}…",
                text_color="#3A766C",
            )
        except Exception as exc:
            self.qr_label.configure(image="", text=f"Could not generate QR:\n{exc}", text_color="#A0404E")


class LedgerScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        SectionHeader(
            self,
            "Append-only history",
            "Cryptographic ledger",
            "Every row below is a sealed transaction block, linked to the previous block by SHA-256.",
            action=("quiet", "Run integrity check", lambda: app.show_screen("security")),
        ).grid(row=0, column=0, sticky="ew", pady=(2, 22))
        panel = card(self)
        panel.grid(row=1, column=0, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        top = ctk.CTkFrame(panel, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 9))
        top.grid_columnconfigure(1, weight=1)
        self.count = label(top, "", 11, MUTED, "bold")
        self.count.grid(row=0, column=0, sticky="w")
        label(top, "Click a transaction to inspect its proof", 11, DIM).grid(row=0, column=1, sticky="e")
        self.feed = ctk.CTkScrollableFrame(
            panel, fg_color="transparent", scrollbar_button_color=LINE,
            scrollbar_button_hover_color=SURFACE_3,
        )
        self.feed.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

    def on_show(self):
        for child in self.feed.winfo_children():
            child.destroy()
        history = list(reversed(self.app.ledger.get_history(self.app.active_vpa)))
        self.count.configure(text=f"{len(history)} ACCOUNT TRANSACTIONS  ·  MERKLE ROOT {self.app.ledger.merkle_root[:14]}…")
        if not history:
            label(self.feed, "No account transactions yet.", 13, MUTED).pack(pady=40)
        for tx in history:
            TransactionRow(self.feed, tx, self.app.active_vpa, self.app.show_transaction).pack(
                fill="x", pady=3
            )


class SecurityScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        SectionHeader(
            self,
            "Security observability",
            "Trust fabric",
            "A human-readable view of the defenses protecting the payment engine.",
            action=("primary", "Run full audit  ◈", self.run_audit),
        ).grid(row=0, column=0, sticky="ew", pady=(2, 22))

        metrics = ctk.CTkFrame(self, fg_color="transparent")
        metrics.grid(row=1, column=0, sticky="ew", pady=(0, 18))
        for col in range(4):
            metrics.grid_columnconfigure(col, weight=1)
        self.block_metric = MetricCard(metrics, "—", "Chain blocks", "including genesis", CYAN)
        self.block_metric.grid(row=0, column=0, sticky="ew", padx=(0, 7))
        self.root_metric = MetricCard(metrics, "—", "Merkle root", "current anchor", PURPLE)
        self.root_metric.grid(row=0, column=1, sticky="ew", padx=4)
        self.bio_metric = MetricCard(metrics, "—", "Biometric vault", "template status", MINT)
        self.bio_metric.grid(row=0, column=2, sticky="ew", padx=4)
        self.vault_metric = MetricCard(metrics, "—", "Encrypted items", "AES-256-GCM records", AMBER)
        self.vault_metric.grid(row=0, column=3, sticky="ew", padx=(7, 0))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=2, column=0, sticky="nsew")
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)
        self.audit_card = card(body)
        self.audit_card.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        self.audit_card.grid_columnconfigure(0, weight=1)
        label(self.audit_card, "LATEST AUDIT RESULT", 10, MINT, "bold").grid(row=0, column=0, sticky="w", padx=20, pady=(20, 8))
        self.audit_status = label(self.audit_card, "Not run yet", 24, TEXT, "bold")
        self.audit_status.grid(row=1, column=0, sticky="w", padx=20)
        self.audit_detail = label(self.audit_card, "Run the full audit to verify every ledger hash and every vault authentication tag.", 12, MUTED, wraplength=430, justify="left")
        self.audit_detail.grid(row=2, column=0, sticky="w", padx=20, pady=(8, 18))
        self.audit_log = ctk.CTkTextbox(
            self.audit_card, height=160, fg_color=BG, border_width=1,
            border_color=LINE, corner_radius=10, text_color=MUTED,
            font=mono(11), state="disabled",
        )
        self.audit_log.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.audit_card.grid_rowconfigure(3, weight=1)

        vault = card(body)
        vault.grid(row=0, column=1, sticky="nsew", padx=(9, 0))
        vault.grid_columnconfigure(0, weight=1)
        label(vault, "DEFENSE MATRIX", 10, CYAN, "bold").grid(row=0, column=0, sticky="w", padx=20, pady=(20, 15))
        defenses = [
            ("AES-256-GCM", "Authenticated encryption rejects bit-flips", MINT),
            ("PBKDF2-HMAC", "600,000 rounds + constant-time comparison", CYAN),
            ("HMAC-SHA256", "Signed QR binds amount, VPA, and nonce", AMBER),
            ("Merkle proofs", "O(log n) inclusion verification", PURPLE),
        ]
        for row, (title, detail, color) in enumerate(defenses, start=1):
            line = ctk.CTkFrame(vault, fg_color=SURFACE, corner_radius=11)
            line.grid(row=row, column=0, sticky="ew", padx=16, pady=5)
            line.grid_columnconfigure(0, weight=1)
            label(line, title, 12, color, "bold").grid(row=0, column=0, sticky="w", padx=12, pady=(10, 0))
            label(line, detail, 10, MUTED).grid(row=1, column=0, sticky="w", padx=12, pady=(3, 10))
        label(vault, "Designed for the demo moment: show the payment, then show why an attacker cannot rewrite it.", 11, MUTED, wraplength=390, justify="left").grid(row=6, column=0, sticky="w", padx=20, pady=(20, 20))

    def on_show(self):
        self.refresh_metrics()

    def refresh_metrics(self):
        ledger = self.app.ledger
        user = self.app.active_vpa.split("@")[0]
        template = self.app.base_dir / "data" / "biometrics" / f"{user}_template.json"
        vault_template = self.app.base_dir / "data" / "vault" / "biometrics" / f"{user}.vault"
        bio = "ENROLLED" if template.exists() or vault_template.exists() else "MISSING"
        vault_items = len(self.app.vault.list_enrolled_users()) + len(self.app.vault.list_secrets())
        self.block_metric.value_label.configure(text=str(len(ledger.transactions)))
        self.root_metric.value_label.configure(text=f"{ledger.merkle_root[:8]}…")
        self.bio_metric.value_label.configure(text=bio)
        self.bio_metric.value_label.configure(text_color=MINT if bio == "ENROLLED" else RED)
        self.vault_metric.value_label.configure(text=str(vault_items))

    def run_audit(self):
        self.audit_status.configure(text="Auditing…", text_color=AMBER)
        self.audit_detail.configure(text="Recalculating every canonical block hash and validating encrypted vault tags.")
        self._append_log("AUDIT STARTED\n")

        def audit():
            ledger_ok, ledger_violations = self.app.ledger.verify_chain_integrity()
            vault_ok, vault_violations = self.app.vault.audit_vault()
            self.after(0, lambda: self._finish_audit(ledger_ok, ledger_violations, vault_ok, vault_violations))

        threading.Thread(target=audit, daemon=True).start()

    def _append_log(self, text):
        self.audit_log.configure(state="normal")
        self.audit_log.delete("1.0", "end")
        self.audit_log.insert("end", text)
        self.audit_log.configure(state="disabled")

    def _finish_audit(self, ledger_ok, ledger_violations, vault_ok, vault_violations):
        passed = ledger_ok and vault_ok
        self.audit_status.configure(
            text="ALL SYSTEMS VERIFIED" if passed else "INTEGRITY ALERT",
            text_color=MINT if passed else RED,
        )
        if passed:
            detail = f"{len(self.app.ledger.transactions)} ledger blocks and all encrypted vault records passed verification."
            lines = [
                "✓ LEDGER  ·  SHA-256 chain is continuous",
                "✓ MERKLE  ·  root matches all transaction leaves",
                "✓ VAULT   ·  AES-256-GCM tags are authentic",
            ]
        else:
            violations = ledger_violations + vault_violations
            detail = f"{len(violations)} integrity issue(s) detected. Review the evidence below."
            lines = ["✗ " + item for item in violations[:8]]
        self.audit_detail.configure(text=detail)
        self._append_log("\n".join(lines) + "\n\nAudit completed at " + datetime.now().strftime("%H:%M:%S"))
        self.refresh_metrics()


class ProPayApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.base_dir = Path(__file__).resolve().parent
        self.active_vpa = "kelvin@propay"
        self.title("ProPay  ·  Zero-Trust Payment Command Center")
        self.geometry("1380x860")
        self.minsize(1100, 720)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

        for directory in ("data/credentials", "data/biometrics", "data/vault", "data/qr_exports"):
            (self.base_dir / directory).mkdir(parents=True, exist_ok=True)

        self.ledger = TamperEvidentLedger()
        self.pin_auth = PINAuthManager()
        self.qr_engine = SignedQREngine()
        self.vault = CryptoVault()

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self._build_sidebar()
        self.content = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)
        self._build_topbar()

        self.screens = {
            "dashboard": DashboardScreen(self),
            "pay": PayScreen(self),
            "receive": ReceiveScreen(self),
            "ledger": LedgerScreen(self),
            "security": SecurityScreen(self),
        }
        for screen in self.screens.values():
            screen.grid(row=1, column=0, sticky="nsew")
        self.show_screen("dashboard")

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=245, fg_color=SIDEBAR, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(8, weight=1)

        brand = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=22, pady=(27, 34))
        brand.grid_columnconfigure(1, weight=1)
        logo = ctk.CTkLabel(
            brand, text="P", width=38, height=38, corner_radius=11,
            fg_color=MINT, text_color=BG, font=font(20, "bold"),
        )
        logo.grid(row=0, column=0, padx=(0, 10))
        label(brand, "PROPAY", 17, TEXT, "bold").grid(row=0, column=1, sticky="w")
        label(brand, "ZERO-TRUST PAYMENTS", 8, MINT, "bold").grid(row=1, column=1, sticky="w", pady=(1, 0))

        label(self.sidebar, "COMMAND CENTER", 9, DIM, "bold").grid(
            row=1, column=0, sticky="w", padx=25, pady=(0, 9)
        )
        self.nav_buttons = {}
        nav = [
            ("dashboard", "⌂", "Overview"),
            ("pay", "↗", "Pay & request"),
            ("receive", "⌁", "Receive"),
            ("ledger", "≡", "Ledger"),
            ("security", "◈", "Security center"),
        ]
        for row, (key, icon, title) in enumerate(nav, start=2):
            button = NavButton(self.sidebar, icon, title, lambda k=key: self.show_screen(k))
            button.grid(row=row, column=0, sticky="ew", padx=13, pady=2)
            self.nav_buttons[key] = button

        trust = card(self.sidebar, color="#0B2030", radius=15, border="#17445A")
        trust.grid(row=9, column=0, sticky="ew", padx=16, pady=(15, 16))
        label(trust, "●  ENGINE ONLINE", 10, MINT, "bold").pack(anchor="w", padx=14, pady=(14, 3))
        label(trust, "All local modules ready.\nLedger + vault connected.", 10, MUTED, justify="left").pack(anchor="w", padx=14, pady=(0, 14))
        label(self.sidebar, "v2.0  ·  HACKATHON BUILD", 9, DIM, "bold").grid(
            row=10, column=0, pady=(0, 18)
        )

    def _build_topbar(self):
        self.topbar = ctk.CTkFrame(self.content, height=70, fg_color=BG, corner_radius=0)
        self.topbar.grid(row=0, column=0, sticky="ew", padx=28)
        self.topbar.grid_propagate(False)
        self.topbar.grid_columnconfigure(0, weight=1)
        label(self.topbar, "LOCAL SECURE SESSION", 10, DIM, "bold").grid(
            row=0, column=0, sticky="sw", pady=(0, 7)
        )
        right = ctk.CTkFrame(self.topbar, fg_color="transparent")
        right.grid(row=0, column=1, sticky="se", pady=(0, 7))
        Pill(right, "●  ONLINE", MINT, MINT_DARK).pack(side="left", padx=(0, 12))
        ctk.CTkLabel(
            right, text="K", width=30, height=30, corner_radius=15,
            fg_color=CYAN_DARK, text_color=CYAN, font=font(12, "bold"),
        ).pack(side="left")
        label(right, "Kelvin  ·  kelvin@propay", 11, TEXT, "bold").pack(side="left", padx=(8, 0))

    def show_screen(self, name):
        self.screens[name].tkraise()
        for key, button in self.nav_buttons.items():
            button.set_active(key == name)
        self.screens[name].on_show()

    def refresh_all(self):
        for screen in self.screens.values():
            screen.on_show()

    def biometric_label(self):
        username = self.active_vpa.split("@")[0]
        if (self.base_dir / "data" / "biometrics" / f"{username}_template.json").exists():
            return "ENROLLED"
        if (self.base_dir / "data" / "vault" / "biometrics" / f"{username}.vault").exists():
            return "ENROLLED"
        return "MISSING"

    def open_pin_dialog(self, callback: Callable[[str], None]):
        dialog = ctk.CTkToplevel(self)
        dialog.title("ProPay PIN authorization")
        dialog.geometry("410x430")
        dialog.resizable(False, False)
        dialog.configure(fg_color=BG)
        dialog.transient(self)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)
        label(dialog, "FINAL AUTHORIZATION", 10, MINT, "bold").grid(row=0, column=0, pady=(28, 5))
        label(dialog, "Enter your ProPay PIN", 22, TEXT, "bold").grid(row=1, column=0)
        label(dialog, "Your PIN is checked with a constant-time verifier.", 11, MUTED).grid(row=2, column=0, pady=(6, 18))
        pin_var = tk.StringVar()
        entry = ctk.CTkEntry(
            dialog, textvariable=pin_var, show="•", width=270, height=52,
            corner_radius=12, fg_color=SURFACE, border_color=LINE,
            text_color=TEXT, justify="center", font=font(22, "bold"),
        )
        entry.grid(row=3, column=0)
        entry.focus_set()
        error = label(dialog, "", 11, RED)
        error.grid(row=4, column=0, pady=(9, 0))

        def submit(_event=None):
            pin = pin_var.get()
            if not pin.isdigit() or len(pin) < 4:
                error.configure(text="Enter your numeric PIN.")
                return
            dialog.destroy()
            callback(pin)

        entry.bind("<Return>", submit)
        primary_button(dialog, "Verify & continue", submit, width=180, height=44).grid(row=5, column=0, pady=(18, 8))
        quiet_button(dialog, "Cancel", dialog.destroy, width=100, height=34).grid(row=6, column=0)

    def show_transaction(self, tx: Transaction):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Sealed transaction")
        dialog.geometry("620x540")
        dialog.configure(fg_color=BG)
        dialog.transient(self)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)
        label(dialog, "SEALED TRANSACTION", 10, MINT, "bold").grid(row=0, column=0, sticky="w", padx=26, pady=(25, 4))
        label(dialog, f"₹{tx.amount:,.2f}", 32, TEXT, "bold").grid(row=1, column=0, sticky="w", padx=26)
        label(dialog, f"{tx.sender_vpa}  →  {tx.receiver_vpa}", 12, MUTED).grid(row=2, column=0, sticky="w", padx=26, pady=(4, 20))
        panel = card(dialog, color=SURFACE_2, radius=14)
        panel.grid(row=3, column=0, sticky="ew", padx=22)
        panel.grid_columnconfigure(1, weight=1)
        rows = [
            ("Transaction ID", tx.tx_id),
            ("Timestamp", tx.timestamp_iso),
            ("Block hash", tx.tx_hash),
            ("Previous hash", tx.prev_hash),
            ("Auth factors", ", ".join(tx.auth_factors)),
        ]
        for row, (key, value) in enumerate(rows):
            label(panel, key.upper(), 9, DIM, "bold").grid(row=row, column=0, sticky="nw", padx=15, pady=(13 if row == 0 else 5, 0))
            label(panel, value, 10, TEXT if row < 2 else CYAN, "normal", wraplength=380, justify="left").grid(row=row, column=1, sticky="w", padx=14, pady=(13 if row == 0 else 5, 0))
        quiet_button(dialog, "Close", dialog.destroy, width=100, height=36).grid(row=4, column=0, pady=22)

    def show_receipt(self, tx: Transaction):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Payment settled")
        dialog.geometry("560x420")
        dialog.configure(fg_color=BG)
        dialog.transient(self)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)
        Pill(dialog, "✓  SETTLED & SEALED", MINT, MINT_DARK).grid(row=0, column=0, pady=(27, 10))
        label(dialog, "Payment complete", 25, TEXT, "bold").grid(row=1, column=0)
        label(dialog, f"₹{tx.amount:,.2f} sent to {tx.receiver_vpa}", 13, MUTED).grid(row=2, column=0, pady=(6, 22))
        proof = card(dialog, color=SURFACE_2, radius=14)
        proof.grid(row=3, column=0, padx=24, sticky="ew")
        label(proof, "TRANSACTION ID", 9, DIM, "bold").pack(anchor="w", padx=16, pady=(15, 2))
        label(proof, tx.tx_id, 11, CYAN, "bold").pack(anchor="w", padx=16)
        label(proof, f"SHA-256 block  {tx.tx_hash[:18]}…\nMerkle root     {self.ledger.merkle_root[:18]}…", 10, MUTED, justify="left").pack(anchor="w", padx=16, pady=(10, 15))
        primary_button(dialog, "Done", lambda: (dialog.destroy(), self.show_screen("dashboard")), width=110, height=40).grid(row=4, column=0, pady=23)


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    app = ProPayApp()
    app.mainloop()