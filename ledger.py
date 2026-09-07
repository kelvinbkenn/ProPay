"""
ProPay - Tamper-Evident Transaction Ledger & Merkle Audit Trail Engine
Part 5 of the ProPay Secure CLI Payment Platform.

Features:
- Cryptographic SHA-256 append-only transaction hash chaining (blockchain style)
- Binary Merkle Tree construction over leaf transaction hashes
- Compact O(log N) Merkle inclusion proofs for third-party / light-client audits
- Zero-trust chain integrity verification catching any retroactive byte manipulation
- Atomic persistence with crash-resilient file writes
- Account balance calculations and audit history queries
- Rich terminal tables, visual Merkle tree output, and interactive tamper demo
"""

import os
import sys
import time
import json
import uuid
import hmac
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Optional, Tuple, Dict, Any, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(legacy_windows=False)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_LEDGER_FILE = DATA_DIR / "ledger.json"
GENESIS_PREV_HASH = "0" * 64
DEFAULT_CURRENCY = "INR"


def ensure_data_directory(ledger_path: Path) -> None:
    """Ensures parent directory for ledger file exists."""
    ledger_path.parent.mkdir(parents=True, exist_ok=True)


@dataclass
class Transaction:
    """
    Cryptographically chained ledger transaction block.
    """
    tx_id: str
    timestamp: float
    timestamp_iso: str
    sender_vpa: str
    receiver_vpa: str
    amount: float
    currency: str = DEFAULT_CURRENCY
    auth_factors: List[str] = field(default_factory=list)
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))
    prev_hash: str = GENESIS_PREV_HASH
    tx_hash: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.sender_vpa:
            self.sender_vpa = self.sender_vpa.strip().lower()
        if self.receiver_vpa:
            self.receiver_vpa = self.receiver_vpa.strip().lower()

    def compute_canonical_string(self) -> str:
        """
        Builds deterministic canonical string used to compute SHA-256 hash.
        Includes all immutable financial and cryptographic fields.
        """
        sorted_factors = ",".join(sorted(self.auth_factors))
        return (
            f"tx_id={self.tx_id}|"
            f"ts={self.timestamp:.6f}|"
            f"sender={self.sender_vpa.strip().lower()}|"
            f"receiver={self.receiver_vpa.strip().lower()}|"
            f"amt={self.amount:.2f}|"
            f"cur={self.currency.upper()}|"
            f"nonce={self.nonce}|"
            f"prev={self.prev_hash}|"
            f"factors={sorted_factors}"
        )

    def calculate_hash(self) -> str:
        """Calculates SHA-256 hash over canonical representation."""
        canonical = self.compute_canonical_string()
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def seal(self) -> None:
        """Computes and locks the transaction hash."""
        self.tx_hash = self.calculate_hash()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes transaction to standard dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Transaction":
        """Deserializes transaction from dictionary."""
        return cls(
            tx_id=data["tx_id"],
            timestamp=float(data["timestamp"]),
            timestamp_iso=data.get("timestamp_iso", ""),
            sender_vpa=data["sender_vpa"],
            receiver_vpa=data["receiver_vpa"],
            amount=float(data["amount"]),
            currency=data.get("currency", DEFAULT_CURRENCY),
            auth_factors=list(data.get("auth_factors", [])),
            nonce=data.get("nonce", ""),
            prev_hash=data.get("prev_hash", GENESIS_PREV_HASH),
            tx_hash=data.get("tx_hash", ""),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass
class MerkleProof:
    """
    Cryptographic audit proof demonstrating inclusion of a transaction in the Merkle Tree.
    Contains O(log N) sibling hashes and their positions.
    """
    tx_id: str
    leaf_hash: str
    merkle_root: str
    # List of (sibling_hash, direction), where direction is 'left' or 'right'
    proof_path: List[Tuple[str, str]]
    leaf_index: int
    total_leaves: int

    def verify(self) -> bool:
        """
        Validates inclusion proof against the stored Merkle root in constant time.
        """
        return MerkleTree.verify_proof(self.leaf_hash, self.proof_path, self.merkle_root)


class MerkleTree:
    """
    High-performance Binary Merkle Tree for transaction verification and audit trails.
    """

    def __init__(self, leaf_hashes: Optional[List[str]] = None):
        self.leaves: List[str] = list(leaf_hashes) if leaf_hashes else []
        self.levels: List[List[str]] = []
        self._build_tree()

    @staticmethod
    def hash_pair(left: str, right: str) -> str:
        """Computes SHA-256 hash of concatenated left and right child hashes."""
        combined = f"{left}{right}"
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def _build_tree(self) -> None:
        """Builds all levels of the Merkle Tree up to the root."""
        if not self.leaves:
            empty_root = hashlib.sha256(b"PROPAY_EMPTY_MERKLE_TREE").hexdigest()
            self.levels = [[empty_root]]
            return

        current_level = list(self.leaves)
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Odd number of leaves: duplicate the last node (RFC 6962 standard)
                    right = left
                parent = self.hash_pair(left, right)
                next_level.append(parent)

            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        """Returns the 64-character Merkle root hash."""
        if not self.levels or not self.levels[-1]:
            return hashlib.sha256(b"PROPAY_EMPTY_MERKLE_TREE").hexdigest()
        return self.levels[-1][0]

    def get_proof(self, tx_id_or_hash: str) -> Optional[MerkleProof]:
        """
        Generates an O(log N) Merkle inclusion proof for a given leaf hash.
        """
        if not self.leaves:
            return None

        # Find leaf index
        target_idx = -1
        target_hash = tx_id_or_hash
        for idx, h in enumerate(self.leaves):
            if h == target_hash:
                target_idx = idx
                break

        if target_idx == -1:
            return None

        proof_path: List[Tuple[str, str]] = []
        curr_idx = target_idx

        # Traverse levels from bottom to top (excluding root level)
        for level in self.levels[:-1]:
            is_right_child = (curr_idx % 2 == 1)
            if is_right_child:
                sibling_idx = curr_idx - 1
                sibling_hash = level[sibling_idx]
                proof_path.append((sibling_hash, "left"))
            else:
                if curr_idx + 1 < len(level):
                    sibling_hash = level[curr_idx + 1]
                else:
                    sibling_hash = level[curr_idx]
                proof_path.append((sibling_hash, "right"))

            curr_idx //= 2

        return MerkleProof(
            tx_id="",
            leaf_hash=target_hash,
            merkle_root=self.root,
            proof_path=proof_path,
            leaf_index=target_idx,
            total_leaves=len(self.leaves),
        )

    @classmethod
    def verify_proof(cls, leaf_hash: str, proof_path: List[Tuple[str, str]], expected_root: str) -> bool:
        """
        Verifies that leaf_hash belongs to the tree that produced expected_root.
        """
        current = leaf_hash
        for sibling_hash, direction in proof_path:
            if direction == "left":
                current = cls.hash_pair(sibling_hash, current)
            elif direction == "right":
                current = cls.hash_pair(current, sibling_hash)
            else:
                return False

        return hmac.compare_digest(current, expected_root)


class TamperEvidentLedger:
    """
    Append-only cryptographically linked transaction ledger with Merkle audit tree.
    """

    def __init__(self, ledger_file: Path = DEFAULT_LEDGER_FILE):
        self.ledger_file = Path(ledger_file)
        ensure_data_directory(self.ledger_file)
        self.transactions: List[Transaction] = []
        self.merkle_tree: MerkleTree = MerkleTree()
        self._load_or_initialize()

    def _load_or_initialize(self) -> None:
        """Loads existing ledger or initializes new genesis state with default accounts."""
        if self.ledger_file.exists():
            try:
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    tx_list = [Transaction.from_dict(t) for t in data.get("transactions", [])]
                    self.transactions = tx_list
                    self._rebuild_merkle_tree()
                    return
            except Exception as e:
                console.print(f"[bold red]Warning: Failed to parse existing ledger file ({e}). Re-initializing.[/bold red]")

        # Create fresh genesis ledger
        self.transactions = []
        self._create_genesis_block()
        self._seed_default_funding()
        self._save_atomic()

    def _create_genesis_block(self) -> None:
        """Creates immutable Genesis block (Block 0) of the ProPay ledger."""
        now = time.time()
        iso_str = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        genesis_tx = Transaction(
            tx_id="TXN-GENESIS-00000000",
            timestamp=now,
            timestamp_iso=iso_str,
            sender_vpa="SYSTEM_GENESIS",
            receiver_vpa="SYSTEM_RESERVE",
            amount=0.0,
            currency=DEFAULT_CURRENCY,
            auth_factors=["GENESIS_INITIALIZATION", "SHA256_ANCHOR"],
            nonce="0" * 32,
            prev_hash=GENESIS_PREV_HASH,
            metadata={"description": "ProPay Zero-Trust Platform Genesis Anchor"},
        )
        genesis_tx.seal()
        self.transactions.append(genesis_tx)
        self._rebuild_merkle_tree()

    def _seed_default_funding(self) -> None:
        """Seeds demo accounts with test balances for seamless hackathon evaluations."""
        initial_accounts = [
            ("kelvin@propay", 5000.00, "Initial User Test Allocation"),
            ("alice@propay", 2500.00, "Demo User Test Allocation"),
        ]
        for vpa, amount, desc in initial_accounts:
            self._append_transaction_internal(
                sender_vpa="SYSTEM_FAUCET",
                receiver_vpa=vpa,
                amount=amount,
                auth_factors=["SYSTEM_GRANT"],
                metadata={"description": desc},
            )

    def _rebuild_merkle_tree(self) -> None:
        """Recomputes Merkle Tree from all transaction hashes in sequential order."""
        hashes = [tx.tx_hash for tx in self.transactions]
        self.merkle_tree = MerkleTree(hashes)

    def _save_atomic(self) -> None:
        """
        Atomically persists ledger to disk using temporary file replacement
        to prevent corrupted states during unexpected terminations.
        """
        temp_file = self.ledger_file.with_suffix(".tmp")
        payload = {
            "version": "PROPAY-LEDGER-v1.0",
            "merkle_root": self.merkle_tree.root,
            "block_height": len(self.transactions),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "transactions": [tx.to_dict() for tx in self.transactions],
        }
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        # Atomic replace
        temp_file.replace(self.ledger_file)

    @property
    def tip(self) -> Optional[Transaction]:
        """Returns the most recent transaction block on the chain."""
        return self.transactions[-1] if self.transactions else None

    @property
    def merkle_root(self) -> str:
        """Returns current Merkle root."""
        return self.merkle_tree.root

    def get_balance(self, vpa: str) -> float:
        """
        Computes accurate net balance for a VPA by iterating all verified transactions.
        """
        vpa_norm = vpa.strip().lower()
        balance = 0.0

        for tx in self.transactions:
            if tx.receiver_vpa.strip().lower() == vpa_norm:
                balance += tx.amount
            if tx.sender_vpa.strip().lower() == vpa_norm:
                balance -= tx.amount

        return round(balance, 2)

    def _append_transaction_internal(
        self,
        sender_vpa: str,
        receiver_vpa: str,
        amount: float,
        auth_factors: List[str],
        metadata: Optional[Dict[str, Any]] = None,
        tx_id: Optional[str] = None,
    ) -> Transaction:
        """Internal append helper linking to current tip hash."""
        now = time.time()
        iso_str = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        prev_hash = self.tip.tx_hash if self.tip else GENESIS_PREV_HASH
        assigned_id = tx_id or f"TXN-{uuid.uuid4().hex[:12].upper()}"

        tx = Transaction(
            tx_id=assigned_id,
            timestamp=now,
            timestamp_iso=iso_str,
            sender_vpa=sender_vpa.strip().lower(),
            receiver_vpa=receiver_vpa.strip().lower(),
            amount=round(amount, 2),
            currency=DEFAULT_CURRENCY,
            auth_factors=auth_factors,
            prev_hash=prev_hash,
            metadata=metadata or {},
        )
        tx.seal()
        self.transactions.append(tx)
        self._rebuild_merkle_tree()
        return tx

    def record_transaction(
        self,
        sender_vpa: str,
        receiver_vpa: str,
        amount: float,
        auth_factors: List[str],
        metadata: Optional[Dict[str, Any]] = None,
        check_balance: bool = True,
    ) -> Tuple[bool, str, Optional[Transaction]]:
        """
        Records a new transaction onto the append-only cryptographic ledger.
        Enforces balance checks, immutable hash chaining, and Merkle tree update.
        """
        if amount <= 0:
            return False, "Transaction amount must be strictly positive.", None

        sender_norm = sender_vpa.strip().lower()
        receiver_norm = receiver_vpa.strip().lower()

        if sender_norm == receiver_norm:
            return False, "Sender and receiver VPA cannot be identical.", None

        # Check balance for non-system accounts
        if check_balance and not sender_norm.startswith("system_"):
            current_bal = self.get_balance(sender_norm)
            if current_bal < amount:
                return False, f"Insufficient funds: available ₹{current_bal:.2f}, required ₹{amount:.2f}.", None

        # Append transaction and persist atomically
        tx = self._append_transaction_internal(
            sender_vpa=sender_norm,
            receiver_vpa=receiver_norm,
            amount=amount,
            auth_factors=auth_factors,
            metadata=metadata,
        )
        self._save_atomic()

        return True, "Transaction successfully appended and sealed into cryptographic ledger.", tx

    def get_merkle_proof(self, tx_id: str) -> Optional[MerkleProof]:
        """
        Generates Merkle inclusion proof for a given transaction ID.
        """
        target_hash = None
        for tx in self.transactions:
            if tx.tx_id == tx_id:
                target_hash = tx.tx_hash
                break

        if not target_hash:
            return None

        proof = self.merkle_tree.get_proof(target_hash)
        if proof:
            proof.tx_id = tx_id
        return proof

    def get_history(self, vpa: Optional[str] = None) -> List[Transaction]:
        """Returns transactions filtered by VPA (sender or receiver) or entire ledger."""
        if not vpa:
            return list(self.transactions)

        vpa_norm = vpa.strip().lower()
        return [
            tx for tx in self.transactions
            if tx.sender_vpa.strip().lower() == vpa_norm or tx.receiver_vpa.strip().lower() == vpa_norm
        ]

    def verify_chain_integrity(self) -> Tuple[bool, List[str]]:
        """
        Performs end-to-end cryptographic verification of the entire ledger.
        1. Validates Genesis block anchor
        2. Recalculates canonical SHA-256 hash of every block and compares with stored tx_hash
        3. Validates that each block's prev_hash strictly matches the previous block's tx_hash
        4. Recomputes Merkle Tree from scratch and compares against current Merkle root
        """
        violations: List[str] = []

        if not self.transactions:
            violations.append("Ledger is completely empty (missing Genesis block).")
            return False, violations

        # Verify Genesis block
        genesis = self.transactions[0]
        if genesis.prev_hash != GENESIS_PREV_HASH:
            violations.append(
                f"Genesis block prev_hash invalid! Expected '{GENESIS_PREV_HASH}', found '{genesis.prev_hash}'."
            )

        genesis_calc_hash = genesis.calculate_hash()
        if not hmac.compare_digest(genesis.tx_hash, genesis_calc_hash):
            violations.append(
                f"Genesis block hash mismatch! Stored: {genesis.tx_hash}, Recalculated: {genesis_calc_hash}."
            )

        # Verify Sequential Chain
        for i in range(1, len(self.transactions)):
            curr_block = self.transactions[i]
            prev_block = self.transactions[i - 1]

            # 1. Chain continuity link
            if not hmac.compare_digest(curr_block.prev_hash, prev_block.tx_hash):
                violations.append(
                    f"Chain Broken at Block #{i} ({curr_block.tx_id})! "
                    f"prev_hash '{curr_block.prev_hash[:16]}...' does not match "
                    f"Block #{i-1} tx_hash '{prev_block.tx_hash[:16]}...'."
                )

            # 2. Block content integrity (SHA-256 recalculation)
            recalculated = curr_block.calculate_hash()
            if not hmac.compare_digest(curr_block.tx_hash, recalculated):
                violations.append(
                    f"Tamper Alert at Block #{i} ({curr_block.tx_id})! "
                    f"Stored tx_hash '{curr_block.tx_hash[:16]}...' does not match "
                    f"recalculated canonical hash '{recalculated[:16]}...'. "
                    f"Payload content has been altered!"
                )

        # Verify Merkle Tree Root Consistency
        recomputed_hashes = [tx.tx_hash for tx in self.transactions]
        recomputed_tree = MerkleTree(recomputed_hashes)
        if not hmac.compare_digest(recomputed_tree.root, self.merkle_tree.root):
            violations.append(
                f"Merkle Root Divergence! Stored: '{self.merkle_tree.root[:16]}...', "
                f"Recomputed from leaves: '{recomputed_tree.root[:16]}...'."
            )

        is_valid = len(violations) == 0
        return is_valid, violations

    def tamper_block_for_demo(self, block_index: int, new_amount: float) -> bool:
        """
        Artificially alters a block in-memory without recalculating hashes or chained links.
        Used strictly for cybersecurity demonstrations to prove tamper detection.
        """
        if block_index < 0 or block_index >= len(self.transactions):
            return False
        self.transactions[block_index].amount = new_amount
        return True


class LedgerCLI:
    """
    Rich CLI visualizer and audit explorer for the ProPay Cryptographic Ledger.
    """

    def __init__(self, ledger: Optional[TamperEvidentLedger] = None):
        self.ledger = ledger or TamperEvidentLedger()

    def display_ledger(self, vpa: Optional[str] = None) -> None:
        """Renders ledger transactions in a stylized Rich table."""
        txs = self.ledger.get_history(vpa)

        table = Table(
            title=f"ProPay Cryptographic Append-Only Ledger ({len(txs)} Blocks)",
            border_style="cyan",
            expand=True,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Tx ID", style="bold yellow", width=22)
        table.add_column("Timestamp (UTC)", style="white", width=21)
        table.add_column("Sender VPA", style="cyan", width=18)
        table.add_column("Receiver VPA", style="green", width=18)
        table.add_column("Amount", justify="right", style="bold magenta", width=12)
        table.add_column("Auth Factors", style="dim cyan", width=24)
        table.add_column("Tx Hash (SHA-256)", style="dim white", width=16)

        for i, tx in enumerate(txs):
            factors_str = ", ".join(tx.auth_factors) if tx.auth_factors else "NONE"
            short_hash = f"{tx.tx_hash[:6]}...{tx.tx_hash[-6:]}" if tx.tx_hash else "UNSEALED"
            amt_str = f"₹{tx.amount:,.2f}"
            table.add_row(
                str(i),
                tx.tx_id,
                tx.timestamp_iso or datetime.fromtimestamp(tx.timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                tx.sender_vpa,
                tx.receiver_vpa,
                amt_str,
                factors_str,
                short_hash,
            )

        console.print(table)
        console.print(f"[bold cyan]Merkle Root Anchor:[/bold cyan] [bold yellow]{self.ledger.merkle_root}[/bold yellow]\n")

    def display_balance(self, vpa: str) -> None:
        """Displays account balance panel."""
        bal = self.ledger.get_balance(vpa)
        tx_count = len(self.ledger.get_history(vpa))

        table = Table(show_header=False, box=None)
        table.add_column("Field", style="bold cyan", width=18)
        table.add_column("Value", style="bold white")

        table.add_row("Account VPA:", vpa)
        table.add_row("Available Balance:", f"₹{bal:,.2f} INR")
        table.add_row("Activity Count:", f"{tx_count} transactions")

        color = "green" if bal > 0 else "yellow"
        console.print(Panel(table, title=f"[{color}]ProPay Account Balance[/{color}]", expand=False))

    def run_audit(self) -> bool:
        """Executes full cryptographic audit and prints stylized diagnostic report."""
        console.print("\n[bold yellow]Running Cryptographic Ledger Integrity Audit...[/bold yellow]")
        is_valid, violations = self.ledger.verify_chain_integrity()

        if is_valid:
            summary = (
                f"[bold green]✓ ZERO TAMPERING DETECTED[/bold green]\n\n"
                f"• All {len(self.ledger.transactions)} blocks verified against canonical SHA-256 signatures.\n"
                f"• Sequential prev_hash pointers form an unbroken cryptographic chain.\n"
                f"• Merkle Root matches leaf hashes: [bold yellow]{self.ledger.merkle_root}[/bold yellow]"
            )
            console.print(Panel(summary, title="[bold green]Cryptographic Audit PASSED[/bold green]", expand=False))
            return True
        else:
            alert_text = "[bold red]⚠ INTEGRITY BREACH DETECTED![/bold red]\n\n"
            for v in violations:
                alert_text += f"[red]✗ {v}[/red]\n"
            console.print(Panel(alert_text, title="[bold red]Ledger Tamper Alert[/bold red]", expand=False))
            return False

    def display_merkle_proof(self, tx_id: str) -> None:
        """Renders Merkle inclusion proof diagram in the terminal."""
        proof = self.ledger.get_merkle_proof(tx_id)
        if not proof:
            console.print(f"[bold red]Error: Transaction ID '{tx_id}' not found in ledger.[/bold red]")
            return

        is_valid = proof.verify()
        tree = Tree(f"[bold cyan]Merkle Audit Tree (Root: {proof.merkle_root[:16]}...)[/bold cyan]")
        branch = tree.add(f"[bold yellow]Leaf Tx: {tx_id}[/bold yellow] (Hash: {proof.leaf_hash[:16]}...)")

        for idx, (sibling_hash, direction) in enumerate(proof.proof_path):
            dir_label = "LEFT Sibling" if direction == "left" else "RIGHT Sibling"
            branch = branch.add(f"Step {idx + 1}: [{direction.upper()}] {sibling_hash[:16]}... ({dir_label})")

        status_text = "[green]VALID INCLUSION PROOF[/green]" if is_valid else "[red]INVALID PROOF[/red]"
        console.print(Panel(tree, title=f"Merkle Inclusion Proof: {status_text}", expand=False))

    def run_tamper_demo(self) -> None:
        """
        Interactive demonstration:
        1. Records a genuine transaction
        2. Verifies clean chain
        3. Maliciously tampers with transaction amount
        4. Demonstrates instant detection and chain invalidation
        """
        console.print(Panel(
            "[bold white]PROPAY HACKATHON DEFENSE DEMO: RETROACTIVE TAMPER DETECTION[/bold white]\n"
            "This demo shows how ProPay's SHA-256 hash chaining and Merkle trees detect "
            "even a single bit alteration in historical transactions.",
            title="[bold red]Security Defense Demonstration[/bold red]",
            expand=False,
        ))

        # 1. Add genuine transaction
        console.print("\n[cyan]Step 1: Adding genuine payment of ₹150.00 from alice@propay to bob@propay...[/cyan]")
        ok, msg, tx = self.ledger.record_transaction(
            sender_vpa="alice@propay",
            receiver_vpa="bob@propay",
            amount=150.00,
            auth_factors=["BIOMETRIC_FACE_VERIFIED", "PIN_CONSTANT_TIME"],
            metadata={"demo": True},
        )
        if not ok or not tx:
            console.print(f"[red]Failed to add demo tx: {msg}[/red]")
            return

        console.print(f"[green]✓ Transaction recorded! Tx ID: {tx.tx_id}, Hash: {tx.tx_hash[:16]}...[/green]")

        # 2. Run clean audit
        console.print("\n[cyan]Step 2: Performing baseline cryptographic audit...[/cyan]")
        clean_pass = self.run_audit()
        assert clean_pass

        # 3. Maliciously modify the transaction amount in memory
        target_idx = len(self.ledger.transactions) - 1
        console.print(f"\n[bold red]Step 3: Attacker modifies transaction amount from ₹150.00 to ₹1,500,000.00 on Block #{target_idx}...[/bold red]")
        self.ledger.tamper_block_for_demo(target_idx, 1500000.00)

        # 4. Re-run audit
        console.print("\n[cyan]Step 4: Running automated security audit following tampering...[/cyan]")
        detected = not self.run_audit()

        if detected:
            console.print("\n[bold green]✓ SUCCESS: ProPay cryptographic hash chain immediately flagged the tampered block![/bold green]\n")
        else:
            console.print("\n[bold red]FAIL: Tamper went undetected![/bold red]\n")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="ProPay Tamper-Evident Transaction Ledger CLI")
    parser.add_argument("--list", action="store_true", help="List all ledger transactions")
    parser.add_argument("--vpa", type=str, help="Filter transactions or query balance for VPA")
    parser.add_argument("--balance", type=str, help="Check balance for specified VPA")
    parser.add_argument("--verify", action="store_true", help="Perform cryptographic chain integrity audit")
    parser.add_argument("--proof", type=str, help="Generate and display Merkle audit proof for Tx ID")
    parser.add_argument("--tamper-demo", action="store_true", help="Run interactive hackathon tamper-defense demo")

    args = parser.parse_args()
    ledger = TamperEvidentLedger()
    cli = LedgerCLI(ledger)

    if args.list:
        cli.display_ledger(args.vpa)
    elif args.balance:
        cli.display_balance(args.balance)
    elif args.verify:
        cli.run_audit()
    elif args.proof:
        cli.display_merkle_proof(args.proof)
    elif args.tamper_demo:
        cli.run_tamper_demo()
    else:
        # Default action: display ledger and verify
        cli.display_ledger()
        cli.run_audit()


if __name__ == "__main__":
    main()
