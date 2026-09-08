"""
ProPay  –  Premium Payment UI
GPay / Instagram aesthetic: deep-black, emerald accent, ultra-clean.

Run:  python UI.py
"""

from __future__ import annotations
import sys, threading, json
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk

# ── backend ───────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ledger   import TamperEvidentLedger
from pin_auth import PINAuthManager
from qr_scanner import SignedQREngine
from crypto_vault import CryptoVault

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── palette ───────────────────────────────────────────────────────────────────
BG          = "#0A0A0F"
CARD        = "#111118"
CARD2       = "#1C1C26"
ACCENT      = "#00D09C"   # cash-app / GPay teal-green
ACCENT_DARK = "#00796B"
RED         = "#FF4757"
RED_DARK    = "#3D1A1E"
WHITE       = "#F5F5F5"
MUTED       = "#6B6B80"
BORDER      = "#2A2A38"
INPUT_BG    = "#16161F"

# ── type scale ────────────────────────────────────────────────────────────────
F_HERO   = ("SF Pro Display", 38, "bold")
F_TITLE  = ("SF Pro Display", 22, "bold")
F_HEAD   = ("SF Pro Display", 17, "bold")
F_BODY   = ("SF Pro Display", 14)
F_SMALL  = ("SF Pro Display", 12)
F_TINY   = ("SF Pro Display", 10)

def _try_font(preferred, fallback_size, weight="normal"):
    """Return preferred if available, else Helvetica."""
    try:
        tk.font.Font(family=preferred)
        return (preferred, fallback_size, weight) if weight != "normal" else (preferred, fallback_size)
    except Exception:
        return ("Helvetica", fallback_size, weight) if weight != "normal" else ("Helvetica", fallback_size)

# ── small helpers ─────────────────────────────────────────────────────────────

def lbl(parent, text, size=13, bold=False, color=WHITE, **kw):
    weight = "bold" if bold else "normal"
    return ctk.CTkLabel(parent, text=text,
                        font=("Helvetica", size, weight),
                        text_color=color, **kw)

def card_frame(parent, **kw):
    kw.setdefault("fg_color",      CARD)
    kw.setdefault("corner_radius", 20)
    kw.setdefault("border_width",  1)
    kw.setdefault("border_color",  BORDER)
    return ctk.CTkFrame(parent, **kw)

def accent_btn(parent, text, command, height=52, font_size=15, **kw):
    kw.setdefault("corner_radius", height // 2)
    return ctk.CTkButton(
        parent, text=text, command=command,
        font=("Helvetica", font_size, "bold"),
        height=height, fg_color=ACCENT,
        hover_color=ACCENT_DARK, text_color="#000000",
        **kw
    )

def ghost_btn(parent, text, command, height=44, **kw):
    kw.setdefault("corner_radius", height // 2)
    return ctk.CTkButton(
        parent, text=text, command=command,
        font=("Helvetica", 13), height=height,
        fg_color=CARD2, hover_color=BORDER,
        text_color=WHITE, border_width=0, **kw
    )

def back_btn(parent, command):
    return ctk.CTkButton(
        parent, text="←", command=command,
        width=40, height=40, corner_radius=20,
        font=("Helvetica", 18), fg_color=CARD2,
        hover_color=BORDER, text_color=WHITE,
    )

# ─────────────────────────────────────────────────────────────────────────────
# PIN Dot Canvas  (always-reliable native drawing)
# ─────────────────────────────────────────────────────────────────────────────

class PINDots(tk.Canvas):
    """Six animated dot indicators drawn directly on a tk.Canvas."""
    FILLED   = ACCENT
    EMPTY    = "#2A2A38"
    R        = 9          # dot radius
    GAP      = 28         # centre-to-centre spacing

    def __init__(self, parent, n=6, **kw):
        total_w = n * self.GAP
        super().__init__(parent, width=total_w, height=28,
                         bg=BG, highlightthickness=0, **kw)
        self.n = n
        self._count = 0
        self._ids: list[int] = []
        cx = self.GAP // 2
        for _ in range(n):
            oid = self.create_oval(
                cx - self.R, 14 - self.R,
                cx + self.R, 14 + self.R,
                fill=self.EMPTY, outline=""
            )
            self._ids.append(oid)
            cx += self.GAP

    def set(self, count: int):
        self._count = max(0, min(count, self.n))
        for i, oid in enumerate(self._ids):
            self.itemconfig(oid, fill=self.FILLED if i < self._count else self.EMPTY)


# ─────────────────────────────────────────────────────────────────────────────
# Screen base
# ─────────────────────────────────────────────────────────────────────────────

class Screen(ctk.CTkFrame):
    def __init__(self, app: "ProPayApp"):
        super().__init__(app, fg_color=BG, corner_radius=0)
        self.app = app
        self.grid(row=0, column=0, sticky="nsew")

    def on_show(self):
        """Called every time this screen becomes visible."""
        pass


# ─────────────────────────────────────────────────────────────────────────────
# LOGIN  SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class LoginScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self._digits: list[str] = []
        self._build()

    # ── layout ───────────────────────────────────────────────────────────────
    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=2)  # top spacer
        self.grid_rowconfigure(1, weight=0)  # logo
        self.grid_rowconfigure(2, weight=0)  # dots
        self.grid_rowconfigure(3, weight=0)  # error
        self.grid_rowconfigure(4, weight=1)  # mid spacer
        self.grid_rowconfigure(5, weight=0)  # keypad
        self.grid_rowconfigure(6, weight=0)  # footer
        self.grid_rowconfigure(7, weight=1)  # bot spacer

        # ── logo block ────────────────────────────────────────────────────
        logo = ctk.CTkFrame(self, fg_color="transparent")
        logo.grid(row=1, column=0)
        lbl(logo, "ProPay", size=36, bold=True, color=WHITE).pack()
        lbl(logo, "Enter your PIN to continue", size=12, color=MUTED).pack(pady=(4, 0))

        # ── dot row ───────────────────────────────────────────────────────
        dot_wrap = ctk.CTkFrame(self, fg_color="transparent")
        dot_wrap.grid(row=2, column=0, pady=(36, 0))
        self._dots = PINDots(dot_wrap)
        self._dots.pack()

        # ── error ─────────────────────────────────────────────────────────
        self._err = lbl(self, "", size=12, color=RED)
        self._err.grid(row=3, column=0, pady=(10, 0))

        # ── keypad ───────────────────────────────────────────────────────
        pad = ctk.CTkFrame(self, fg_color="transparent")
        pad.grid(row=5, column=0, pady=(0, 4))
        rows = [("1","2","3"), ("4","5","6"), ("7","8","9"), ("","0","⌫")]
        for r, trio in enumerate(rows):
            for c, ch in enumerate(trio):
                if ch == "":
                    ctk.CTkFrame(pad, fg_color="transparent",
                                 width=72, height=72).grid(row=r, column=c, padx=10, pady=8)
                else:
                    _KeyBtn(pad, ch, self._press).grid(row=r, column=c, padx=10, pady=8)

        # ── account pill ──────────────────────────────────────────────────
        foot = ctk.CTkFrame(self, fg_color="transparent")
        foot.grid(row=6, column=0, pady=(16, 0))
        self._acct_lbl = lbl(foot, self.app.vpa, size=11, color=MUTED)
        self._acct_lbl.pack(side="left")
        ctk.CTkButton(
            foot, text="switch", font=("Helvetica", 11),
            width=52, height=22, corner_radius=11,
            fg_color="transparent", hover_color=CARD2,
            text_color=ACCENT, border_width=0,
            command=self._switch,
        ).pack(side="left", padx=(6, 0))

    # ── callbacks ─────────────────────────────────────────────────────────────
    def _press(self, ch: str):
        if ch == "⌫":
            if self._digits:
                self._digits.pop()
        elif len(self._digits) < 6:
            self._digits.append(ch)
        self._dots.set(len(self._digits))
        if len(self._digits) == 6:
            self.after(80, self._verify)

    def _verify(self):
        pin = "".join(self._digits)
        self._digits.clear()
        self._dots.set(0)
        ok, msg = self.app.pin_auth.verify_pin(self.app.vpa, pin)
        if ok:
            self.app.show("home")
        else:
            self._err.configure(text=f"Incorrect PIN — {msg}")
            self.after(2200, lambda: self._err.configure(text=""))

    def _switch(self):
        self.app.vpa = "alice@propay" if "kelvin" in self.app.vpa else "kelvin@propay"
        self._acct_lbl.configure(text=self.app.vpa)

    def on_show(self):
        self._digits.clear()
        self._dots.set(0)
        self._err.configure(text="")
        self._acct_lbl.configure(text=self.app.vpa)


class _KeyBtn(ctk.CTkButton):
    """Single round keypad button."""
    def __init__(self, parent, char: str, callback):
        super().__init__(
            parent, text=char,
            width=72, height=72, corner_radius=36,
            font=("Helvetica", 22, "bold"),
            fg_color=CARD2, hover_color=CARD,
            text_color=WHITE, border_width=0,
            command=lambda: callback(char),
        )


# ─────────────────────────────────────────────────────────────────────────────
# HOME  SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class HomeScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)   # txn list expands

        # ── top bar ───────────────────────────────────────────────────────
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=24, pady=(28, 0))
        top.grid_columnconfigure(1, weight=1)

        self._greeting = lbl(top, "Good morning,", size=12, color=MUTED)
        self._greeting.grid(row=0, column=0, sticky="w")
        self._name_lbl = lbl(top, "Kelvin", size=17, bold=True, color=WHITE)
        self._name_lbl.grid(row=1, column=0, sticky="w")

        # Avatar + settings
        right = ctk.CTkFrame(top, fg_color="transparent")
        right.grid(row=0, column=1, rowspan=2, sticky="e")
        ctk.CTkButton(
            right, text="⚙", width=38, height=38, corner_radius=19,
            font=("Helvetica", 16), fg_color=CARD2, hover_color=BORDER,
            text_color=MUTED, border_width=0,
            command=lambda: self.app.show("settings"),
        ).pack(side="right")

        # ── balance card ──────────────────────────────────────────────────
        bal_card = ctk.CTkFrame(self, fg_color=CARD, corner_radius=24,
                                border_width=1, border_color=BORDER)
        bal_card.grid(row=1, column=0, sticky="ew", padx=24, pady=24)
        bal_card.grid_columnconfigure(0, weight=1)

        inner = ctk.CTkFrame(bal_card, fg_color="transparent")
        inner.pack(fill="x", padx=24, pady=(22, 20))
        inner.grid_columnconfigure(0, weight=1)

        lbl(inner, "Total Balance", size=11, color=MUTED).grid(
            row=0, column=0, sticky="w")
        self._secure_pill = _Pill(inner, "● Secured")
        self._secure_pill.grid(row=0, column=1, sticky="e")

        self._bal_lbl = lbl(inner, "₹ —", size=38, bold=True, color=WHITE)
        self._bal_lbl.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 18))

        # ── quick actions ─────────────────────────────────────────────────
        qa = ctk.CTkFrame(inner, fg_color="transparent")
        qa.grid(row=2, column=0, columnspan=2, sticky="ew")
        qa.grid_columnconfigure((0,1,2,3), weight=1)

        _actions = [
            ("Pay",     "↗", ACCENT,   "send"),
            ("Request", "↙", "#818CF8", "receive"),
            ("Scan",    "⊡", "#F472B6", "qr"),
            ("History", "≡", MUTED,    "history"),
        ]
        for col, (name, icon, clr, screen) in enumerate(_actions):
            _ActionTile(qa, icon, name, clr, lambda s=screen: self.app.show(s)
                        ).grid(row=0, column=col)

        # ── recent header ─────────────────────────────────────────────────
        rh = ctk.CTkFrame(self, fg_color="transparent")
        rh.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 10))
        rh.grid_columnconfigure(1, weight=1)
        lbl(rh, "Recent", size=15, bold=True, color=WHITE).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            rh, text="See all →", font=("Helvetica", 11),
            width=64, height=24, corner_radius=12,
            fg_color="transparent", hover_color=CARD2,
            text_color=ACCENT, border_width=0,
            command=lambda: self.app.show("history"),
        ).grid(row=0, column=1, sticky="e")

        # ── transaction feed ──────────────────────────────────────────────
        self._feed = ctk.CTkScrollableFrame(self, fg_color="transparent",
                                             scrollbar_button_color=BORDER,
                                             scrollbar_button_hover_color=CARD2)
        self._feed.grid(row=3, column=0, sticky="nsew", padx=24)
        self._feed.grid_columnconfigure(0, weight=1)

        # ── bottom nav ────────────────────────────────────────────────────
        _BottomNav(self, active="home").grid(
            row=4, column=0, sticky="ew")

    # ── data ─────────────────────────────────────────────────────────────────
    def on_show(self):
        import datetime
        hour = datetime.datetime.now().hour
        g = "Good morning" if hour < 12 else ("Good afternoon" if hour < 17 else "Good evening")
        self._greeting.configure(text=g + ",")
        name = self.app.vpa.split("@")[0].title()
        self._name_lbl.configure(text=name)

        bal = self.app.ledger.get_balance(self.app.vpa)
        self._bal_lbl.configure(text=f"₹ {bal:,.2f}")

        for w in self._feed.winfo_children():
            w.destroy()
        txns = list(reversed(self.app.ledger.get_history(self.app.vpa)))[:6]
        if not txns:
            lbl(self._feed, "No transactions yet", size=13, color=MUTED).pack(pady=32)
        else:
            for i, tx in enumerate(txns):
                _TxnRow(self._feed, tx, self.app.vpa).grid(
                    row=i, column=0, sticky="ew", pady=3)


# ─────────────────────────────────────────────────────────────────────────────
# SEND  SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class SendScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)

        # header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(28, 0))
        hdr.grid_columnconfigure(1, weight=1)
        back_btn(hdr, lambda: self.app.show("home")).grid(row=0, column=0)
        lbl(hdr, "Send Money", size=18, bold=True, color=WHITE).grid(
            row=0, column=1, padx=14, sticky="w")

        # amount display (GPay style — centered big number)
        amt_card = ctk.CTkFrame(self, fg_color="transparent")
        amt_card.grid(row=1, column=0, pady=(32, 0))
        lbl(amt_card, "₹", size=22, color=MUTED).pack(side="left", pady=(12, 0))
        self._amt_var = tk.StringVar(value="0")
        self._amt_display = lbl(amt_card, "0", size=52, bold=True, color=WHITE)
        self._amt_display.pack(side="left")

        # numeric amount pad
        pad = ctk.CTkFrame(self, fg_color="transparent")
        pad.grid(row=2, column=0, pady=(8, 0))
        rows = [("1","2","3"), ("4","5","6"), ("7","8","9"), (".","0","⌫")]
        for r, trio in enumerate(rows):
            for c, ch in enumerate(trio):
                ctk.CTkButton(
                    pad, text=ch, width=80, height=58, corner_radius=16,
                    font=("Helvetica", 18, "bold"),
                    fg_color="transparent", hover_color=CARD2,
                    text_color=WHITE, border_width=0,
                    command=lambda x=ch: self._amt_press(x),
                ).grid(row=r, column=c, padx=6, pady=4)

        # recipient field
        rec = ctk.CTkFrame(self, fg_color="transparent")
        rec.grid(row=3, column=0, sticky="ew", padx=28, pady=(16, 0))
        rec.grid_columnconfigure(0, weight=1)
        lbl(rec, "To", size=11, color=MUTED).grid(row=0, column=0, sticky="w", pady=(0, 4))
        self._vpa_entry = ctk.CTkEntry(
            rec, placeholder_text="UPI ID  e.g. alice@propay",
            font=("Helvetica", 13), height=46, corner_radius=14,
            fg_color=INPUT_BG, border_color=BORDER, border_width=1,
            text_color=WHITE, placeholder_text_color=MUTED,
        )
        self._vpa_entry.grid(row=1, column=0, sticky="ew")

        # status
        self._status = lbl(self, "", size=12, color=RED)
        self._status.grid(row=4, column=0, pady=(10, 0))

        # pay button
        self._pay_btn = accent_btn(self, "Pay Now", self._pay, height=56, font_size=16)
        self._pay_btn.grid(row=6, column=0, sticky="ew", padx=28, pady=(12, 36))

    def _amt_press(self, ch):
        cur = self._amt_var.get()
        if ch == "⌫":
            cur = cur[:-1] or "0"
        elif ch == "." and "." in cur:
            return
        elif cur == "0" and ch != ".":
            cur = ch
        else:
            cur += ch
        self._amt_var.set(cur)
        self._amt_display.configure(text=cur)

    def _pay(self):
        to  = self._vpa_entry.get().strip().lower()
        raw = self._amt_var.get()
        if not to:
            self._status.configure(text="Enter a UPI ID", text_color=RED); return
        try:
            amount = float(raw)
            if amount <= 0: raise ValueError
        except ValueError:
            self._status.configure(text="Enter a valid amount", text_color=RED); return

        bal = self.app.ledger.get_balance(self.app.vpa)
        if bal < amount:
            self._status.configure(
                text=f"Insufficient balance  (available ₹{bal:,.2f})", text_color=RED)
            return

        self._pay_btn.configure(state="disabled", text="Processing…")
        self._status.configure(text="")

        def _do():
            ok, msg, tx = self.app.ledger.record_transaction(
                sender_vpa=self.app.vpa, receiver_vpa=to,
                amount=amount, auth_factors=["UI_PIN_VERIFIED"],
                metadata={"ui": True}, check_balance=True,
            )
            self.after(0, lambda: self._done(ok, msg, tx))

        threading.Thread(target=_do, daemon=True).start()

    def _done(self, ok, msg, tx):
        self._pay_btn.configure(state="normal", text="Pay Now")
        if ok and tx:
            self._vpa_entry.delete(0, "end")
            self._amt_var.set("0")
            self._amt_display.configure(text="0")
            self._status.configure(
                text=f"✓  ₹{tx.amount:,.2f} sent to {tx.receiver_vpa}",
                text_color=ACCENT)
            self.app.screens["home"].on_show()
        else:
            self._status.configure(text=f"✗  {msg}", text_color=RED)

    def on_show(self):
        self._amt_var.set("0")
        self._amt_display.configure(text="0")
        self._status.configure(text="")


# ─────────────────────────────────────────────────────────────────────────────
# QR / RECEIVE  SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class QRScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self._img_ref = None
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(28, 0))
        hdr.grid_columnconfigure(1, weight=1)
        back_btn(hdr, lambda: self.app.show("home")).grid(row=0, column=0)
        lbl(hdr, "Receive Money", size=18, bold=True, color=WHITE).grid(
            row=0, column=1, padx=14, sticky="w")

        # QR card
        qr_card = card_frame(self)
        qr_card.grid(row=1, column=0, padx=28, pady=28, sticky="ew")
        inner = ctk.CTkFrame(qr_card, fg_color="transparent")
        inner.pack(pady=28, padx=28)

        self._vpa_lbl = lbl(inner, self.app.vpa, size=14, bold=True, color=WHITE)
        self._vpa_lbl.pack()
        lbl(inner, "Scan to pay", size=11, color=MUTED).pack(pady=(2, 16))

        # QR image label
        self._qr_lbl = ctk.CTkLabel(
            inner, text="Generating…", width=220, height=220,
            fg_color=INPUT_BG, corner_radius=16, text_color=MUTED,
            font=("Helvetica", 12),
        )
        self._qr_lbl.pack()

        lbl(inner, "HMAC-SHA256 signed · expires in 3 min",
            size=10, color=MUTED).pack(pady=(12, 0))

        # amount request
        amt_row = ctk.CTkFrame(self, fg_color="transparent")
        amt_row.grid(row=2, column=0, sticky="ew", padx=28)
        amt_row.grid_columnconfigure(0, weight=1)
        lbl(amt_row, "Request a specific amount (optional)", size=11, color=MUTED
            ).grid(row=0, column=0, sticky="w", pady=(0, 6))
        self._amt_entry = ctk.CTkEntry(
            amt_row, placeholder_text="₹ amount",
            font=("Helvetica", 14), height=44, corner_radius=12,
            fg_color=INPUT_BG, border_color=BORDER, border_width=1,
            text_color=WHITE, placeholder_text_color=MUTED,
        )
        self._amt_entry.grid(row=1, column=0, sticky="ew")

        accent_btn(self, "Generate QR", self._gen, height=50).grid(
            row=3, column=0, sticky="ew", padx=28, pady=20)

    def _gen(self):
        amt_s = self._amt_entry.get().strip()
        amount = float(amt_s) if amt_s else 1.0
        payload = self.app.qr_engine.generate_payload(
            vpa=self.app.vpa, amount=amount,
            name=self.app.vpa.split("@")[0].title(), ttl_seconds=180,
        )
        try:
            import qrcode
            from PIL import Image, ImageTk
            qr = qrcode.QRCode(version=None, box_size=4, border=2,
                               error_correction=qrcode.constants.ERROR_CORRECT_M)
            qr.add_data(json.dumps(payload))
            qr.make(fit=True)
            img = qr.make_image(fill_color="white", back_color="#16161F")
            img = img.resize((220, 220), Image.NEAREST)
            self._img_ref = ImageTk.PhotoImage(img)
            self._qr_lbl.configure(image=self._img_ref, text="")
        except Exception as e:
            self._qr_lbl.configure(text=f"Error: {e}", image="")

    def on_show(self):
        self._vpa_lbl.configure(text=self.app.vpa)
        self._gen()


# ─────────────────────────────────────────────────────────────────────────────
# HISTORY  SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class HistoryScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(28, 0))
        hdr.grid_columnconfigure(1, weight=1)
        back_btn(hdr, lambda: self.app.show("home")).grid(row=0, column=0)
        lbl(hdr, "Transactions", size=18, bold=True, color=WHITE).grid(
            row=0, column=1, padx=14, sticky="w")

        # summary pills
        self._summary = ctk.CTkFrame(self, fg_color="transparent")
        self._summary.grid(row=1, column=0, sticky="ew", padx=24, pady=20)

        self._feed = ctk.CTkScrollableFrame(
            self, fg_color="transparent",
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=CARD2,
        )
        self._feed.grid(row=2, column=0, sticky="nsew", padx=24, pady=(0, 16))
        self._feed.grid_columnconfigure(0, weight=1)

    def on_show(self):
        for w in self._summary.winfo_children():
            w.destroy()
        for w in self._feed.winfo_children():
            w.destroy()

        history = list(reversed(self.app.ledger.get_history(self.app.vpa)))
        if not history:
            lbl(self._feed, "No transactions yet", size=13, color=MUTED).pack(pady=48)
            return

        sent = sum(t.amount for t in history if t.sender_vpa == self.app.vpa)
        recv = sum(t.amount for t in history if t.receiver_vpa == self.app.vpa)

        # summary bar
        self._summary.grid_columnconfigure((0,1,2), weight=1)
        _StatChip(self._summary, f"₹{sent:,.0f}", "Sent", RED).grid(
            row=0, column=0, padx=4)
        _StatChip(self._summary, str(len(history)), "Total", MUTED).grid(
            row=0, column=1, padx=4)
        _StatChip(self._summary, f"₹{recv:,.0f}", "Received", ACCENT).grid(
            row=0, column=2, padx=4)

        for i, tx in enumerate(history):
            _TxnRow(self._feed, tx, self.app.vpa, detail=True).grid(
                row=i, column=0, sticky="ew", pady=3)


# ─────────────────────────────────────────────────────────────────────────────
# SETTINGS  SCREEN
# ─────────────────────────────────────────────────────────────────────────────

class SettingsScreen(Screen):
    def __init__(self, app):
        super().__init__(app)
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=24, pady=(28, 0))
        hdr.grid_columnconfigure(1, weight=1)
        back_btn(hdr, lambda: self.app.show("home")).grid(row=0, column=0)
        lbl(hdr, "Settings", size=18, bold=True, color=WHITE).grid(
            row=0, column=1, padx=14, sticky="w")

        # profile card
        pc = card_frame(self)
        pc.grid(row=1, column=0, sticky="ew", padx=24, pady=24)
        pf = ctk.CTkFrame(pc, fg_color="transparent")
        pf.pack(fill="x", padx=20, pady=20)
        pf.grid_columnconfigure(1, weight=1)

        # avatar circle (canvas)
        av = tk.Canvas(pf, width=52, height=52, bg=CARD,
                       highlightthickness=0)
        av.grid(row=0, column=0, rowspan=2)
        av.create_oval(2, 2, 50, 50, fill=ACCENT_DARK, outline="")
        av.create_text(26, 27, text="K", fill=ACCENT,
                       font=("Helvetica", 20, "bold"))
        self._av_canvas = av

        self._acct_lbl = lbl(pf, self.app.vpa, size=14, bold=True, color=WHITE)
        self._acct_lbl.grid(row=0, column=1, sticky="w", padx=14)
        lbl(pf, "Active account", size=11, color=MUTED).grid(
            row=1, column=1, sticky="w", padx=14)
        ghost_btn(pf, "Switch account", self._switch, height=36, width=120
                  ).grid(row=0, column=2, rowspan=2)

        # security group
        sec = card_frame(self)
        sec.grid(row=2, column=0, sticky="ew", padx=24)
        sf = ctk.CTkFrame(sec, fg_color="transparent")
        sf.pack(fill="x", padx=20, pady=16)
        lbl(sf, "Security", size=12, bold=True, color=MUTED).pack(anchor="w", pady=(0, 10))
        for icon, title, detail in [
            ("🔐", "Vault",     "AES-256-GCM encrypted"),
            ("🧬", "Biometric", "YuNet + SFace neural engine"),
            ("🔑", "PIN hash",  "PBKDF2-HMAC-SHA256 · 600k iterations"),
            ("🌿", "Ledger",    "SHA-256 chained blocks + Merkle tree"),
        ]:
            row = ctk.CTkFrame(sf, fg_color="transparent")
            row.pack(fill="x", pady=5)
            lbl(row, f"{icon}  {title}", size=13, bold=True, color=WHITE).pack(side="left")
            lbl(row, detail, size=11, color=MUTED).pack(side="right")

        # buttons
        ghost_btn(self, "🔍  Run Security Audit", self._audit, height=48
                  ).grid(row=3, column=0, sticky="ew", padx=24, pady=(20, 8))
        ctk.CTkButton(
            self, text="🔒  Lock & Logout", font=("Helvetica", 13),
            height=48, corner_radius=24, fg_color=RED_DARK,
            hover_color="#5A2020", text_color=RED, border_width=0,
            command=lambda: self.app.show("login"),
        ).grid(row=4, column=0, sticky="ew", padx=24, pady=(0, 12))
        lbl(self, "ProPay v2.0  ·  Zero-Trust UPI",
            size=10, color=MUTED).grid(row=5, column=0, pady=(4, 24))

    def on_show(self):
        self._acct_lbl.configure(text=self.app.vpa)
        name_char = self.app.vpa[0].upper()
        self._av_canvas.itemconfig(2, text=name_char)

    def _switch(self):
        self.app.vpa = "alice@propay" if "kelvin" in self.app.vpa else "kelvin@propay"
        self._acct_lbl.configure(text=self.app.vpa)
        name_char = self.app.vpa[0].upper()
        self._av_canvas.itemconfig(2, text=name_char)
        self.app.screens["home"].on_show()

    def _audit(self):
        ok, violations = self.app.ledger.verify_chain_integrity()
        if ok:
            messagebox.showinfo("✓ Audit Passed",
                "All ledger blocks verified.\nMerkle tree intact.\nNo tampering detected.")
        else:
            messagebox.showwarning("✗ Audit Failed",
                "Violations:\n" + "\n".join(violations[:5]))


# ─────────────────────────────────────────────────────────────────────────────
# Shared sub-widgets
# ─────────────────────────────────────────────────────────────────────────────

class _Pill(ctk.CTkLabel):
    def __init__(self, parent, text, color=ACCENT, **kw):
        super().__init__(
            parent, text=text,
            font=("Helvetica", 10, "bold"),
            fg_color=ACCENT_DARK, text_color=ACCENT,
            corner_radius=8, padx=8, pady=2, **kw
        )


class _ActionTile(ctk.CTkFrame):
    def __init__(self, parent, icon, label_text, color, command):
        super().__init__(parent, fg_color="transparent")
        # icon button
        ctk.CTkButton(
            self, text=icon, width=50, height=50, corner_radius=25,
            font=("Helvetica", 20), fg_color=CARD2,
            hover_color=BORDER, text_color=color, border_width=0,
            command=command,
        ).pack()
        ctk.CTkLabel(
            self, text=label_text, font=("Helvetica", 10),
            text_color=MUTED,
        ).pack(pady=(5, 0))


class _TxnRow(ctk.CTkFrame):
    """Single transaction row widget."""
    def __init__(self, parent, tx, my_vpa: str, detail: bool = False):
        super().__init__(parent, fg_color=CARD, corner_radius=16,
                         border_width=1, border_color=BORDER)
        self.grid_columnconfigure(1, weight=1)

        is_debit = tx.sender_vpa == my_vpa
        clr   = RED   if is_debit else ACCENT
        sign  = "−"   if is_debit else "+"
        icon  = "↗"   if is_debit else "↙"
        other = tx.receiver_vpa if is_debit else tx.sender_vpa

        # icon chip (canvas circle)
        ic = tk.Canvas(self, width=40, height=40, bg=CARD,
                       highlightthickness=0)
        ic.grid(row=0, column=0, rowspan=2 if detail else 1,
                padx=(14, 0), pady=12)
        ic.create_oval(2, 2, 38, 38,
                       fill=RED_DARK if is_debit else ACCENT_DARK, outline="")
        ic.create_text(20, 20, text=icon, fill=clr,
                       font=("Helvetica", 14, "bold"))

        # labels
        ctk.CTkLabel(self, text=other,
                     font=("Helvetica", 13, "bold"),
                     text_color=WHITE, anchor="w"
                     ).grid(row=0, column=1, sticky="w", padx=12, pady=(10, 0))
        ts = tx.timestamp_iso[:16].replace("T", "  ")
        ctk.CTkLabel(self, text=ts if not detail else
                     f"{ts}  ·  {tx.tx_id[:14]}…",
                     font=("Helvetica", 10), text_color=MUTED, anchor="w"
                     ).grid(row=1, column=1, sticky="w", padx=12, pady=(0, 10))

        # amount
        ctk.CTkLabel(
            self, text=f"{sign}₹{tx.amount:,.2f}",
            font=("Helvetica", 14, "bold"), text_color=clr,
        ).grid(row=0, column=2, rowspan=2, padx=14)


class _StatChip(ctk.CTkFrame):
    def __init__(self, parent, value, title, color):
        super().__init__(parent, fg_color=CARD, corner_radius=16,
                         border_width=1, border_color=BORDER)
        ctk.CTkLabel(self, text=value,
                     font=("Helvetica", 16, "bold"),
                     text_color=color).pack(pady=(14, 2))
        ctk.CTkLabel(self, text=title,
                     font=("Helvetica", 10),
                     text_color=MUTED).pack(pady=(0, 12))


class _BottomNav(ctk.CTkFrame):
    ITEMS = [
        ("🏠", "Home",    "home"),
        ("↗",  "Pay",     "send"),
        ("⊡",  "QR",      "qr"),
        ("≡",  "History", "history"),
    ]
    def __init__(self, parent, active="home"):
        super().__init__(parent, fg_color=CARD, corner_radius=0,
                         border_width=1, border_color=BORDER, height=68)
        app = parent.app
        self.grid_columnconfigure(tuple(range(len(self.ITEMS))), weight=1)
        for col, (icon, name, screen) in enumerate(self.ITEMS):
            is_active = screen == active
            clr = ACCENT if is_active else MUTED
            f = ctk.CTkFrame(self, fg_color="transparent")
            f.grid(row=0, column=col, pady=8)
            ctk.CTkButton(
                f, text=icon, width=32, height=32, font=("Helvetica", 16),
                fg_color="transparent", hover_color=CARD2,
                text_color=clr, border_width=0,
                command=lambda s=screen: app.show(s),
            ).pack()
            ctk.CTkLabel(f, text=name, font=("Helvetica", 9),
                         text_color=clr).pack()


# ─────────────────────────────────────────────────────────────────────────────
# APP  ROOT
# ─────────────────────────────────────────────────────────────────────────────

class ProPayApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ProPay")
        self.geometry("400x780")
        self.minsize(360, 680)
        self.resizable(True, True)
        self.configure(fg_color=BG)

        # Ensure data dirs
        base = Path(__file__).resolve().parent
        for d in ["data/credentials", "data/biometrics", "data/vault"]:
            (base / d).mkdir(parents=True, exist_ok=True)

        # Backend
        self.vpa       = "kelvin@propay"
        self.ledger    = TamperEvidentLedger()
        self.pin_auth  = PINAuthManager()
        self.qr_engine = SignedQREngine()
        self.vault     = CryptoVault()

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.screens: dict[str, Screen] = {}
        for name, cls in [
            ("login",    LoginScreen),
            ("home",     HomeScreen),
            ("send",     SendScreen),
            ("receive",  QRScreen),
            ("qr",       QRScreen),
            ("history",  HistoryScreen),
            ("settings", SettingsScreen),
        ]:
            s = cls(self)
            self.screens[name] = s

        self.show("login")

    def show(self, name: str):
        s = self.screens[name]
        s.tkraise()
        s.on_show()


if __name__ == "__main__":
    app = ProPayApp()
    app.mainloop()
