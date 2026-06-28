#!/usr/bin/env python3
import sys
import socket

if len(sys.argv) < 3:
    sys.exit(1)
try:
    _port = int(sys.argv[1])
except ValueError:
    sys.exit(1)

_server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
_server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
_server_sock.bind(("", _port))
_server_sock.listen(128)

import hashlib
import json
import math
import queue
import re
import struct
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

GENESIS_PREVIOUS_HASH = "0" * 64
JSON_KWARGS = {"sort_keys": True, "indent": 2, "separators": (",", ": ")}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
MESSAGE_RE = re.compile(r"^[\x20-\x7e]*$")

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, **JSON_KWARGS)

def compute_block_hash(block: Dict[str, Any]) -> str:
    content = {k: v for k, v in block.items() if k != "current_hash"}
    return hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()

def make_genesis_block() -> Dict[str, Any]:
    block = {
        "index": 1,
        "transactions": [],
        "previous_hash": GENESIS_PREVIOUS_HASH,
    }
    block["current_hash"] = compute_block_hash(block)
    return block

def recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    data = bytearray()
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError("peer disconnected")
        data.extend(chunk)
    return bytes(data)

def send_framed(sock: socket.socket, obj: Dict[str, Any]) -> None:
    body = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if len(body) > 0xFFFF:
        raise ValueError("message too large")
    sock.sendall(struct.pack("!H", len(body)) + body)

def recv_framed(sock: socket.socket) -> Dict[str, Any]:
    header = recv_exact(sock, 2)
    length = struct.unpack("!H", header)[0]
    body = recv_exact(sock, length)
    return json.loads(body.decode("utf-8"))

def send_bool(sock: socket.socket, value: bool) -> None:
    sock.sendall(json.dumps(value).encode("utf-8"))

def recv_bool(sock: socket.socket) -> bool:
    data = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("peer disconnected")
        data.extend(chunk)
        try:
            return json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            if len(data) > 16:
                raise

def normalize_host(host: str) -> str:
    if host in ("localhost", "127.0.0.1", "0.0.0.0", ""):
        return "127.0.0.1"
    return host

def peer_key(host: str, port: int) -> Tuple[str, int]:
    return (normalize_host(host), port)

class BlockchainNode:
    def __init__(self, port: int, peer_file: str, pre_bound_socket: socket.socket) -> None:
        self.port = port
        self.self_key = peer_key("127.0.0.1", port)

        self.all_peers = self._load_peers(peer_file)
        if self.self_key in self.all_peers:
            self.remote_peers = [p for p in self.all_peers if p != self.self_key]
            self.n = len(self.all_peers)
        else:
            self.remote_peers = list(self.all_peers)
            self.n = len(self.remote_peers) + 1
        self.f = math.ceil(self.n / 2) - 1

        self.lock = threading.Lock()
        self.chain: List[Dict[str, Any]] = [make_genesis_block()]
        self.sender_nonces: Dict[str, int] = {}
        self.pool: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.logged_txs: Set[Tuple[str, int]] = set()

        self.peer_socks: Dict[Tuple[str, int], socket.socket] = {}
        self.sock_peers: Dict[int, Tuple[str, int]] = {}
        self.values_waiters: Dict[int, "queue.Queue[List[Any]]"] = {}
        self.sock_io_locks: Dict[int, threading.Lock] = {}
        self.crashed: Set[Tuple[str, int]] = set()
        self.sock_lock = threading.Lock()

        self.running = True
        self.in_consensus = False
        self.current_proposal: Optional[Dict[str, Any]] = None
        self.round_proposals: Dict[str, Dict[str, Any]] = {}
        self.round_proposals_lock = threading.Lock()
        self.consensus_event = threading.Event()
        self.consensus_lock = threading.Lock()
        self._stdout_lock = threading.Lock()

        self.server_sock = pre_bound_socket

    def _load_peers(self, path: str) -> List[Tuple[str, int]]:
        peers: List[Tuple[str, int]] = []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or ":" not in line:
                        continue
                    host, port_str = line.rsplit(":", 1)
                    try:
                        p = int(port_str)
                    except ValueError:
                        continue
                    if p != self.port:
                        peers.append(peer_key(host, p))
        except OSError:
            pass
        return peers

    def confirmed_nonce(self, sender: str) -> int:
        return self.sender_nonces.get(sender, 0)

    def _validate_fields(self, tx: Dict[str, Any]) -> bool:
        if not isinstance(tx, dict):
            return False
        if set(tx.keys()) != {"sender", "message", "nonce", "signature"}:
            return False
        sender = tx["sender"]
        message = tx["message"]
        nonce = tx["nonce"]
        signature = tx["signature"]
        if not isinstance(sender, str) or not HEX64.match(sender):
            return False
        if not isinstance(message, str) or len(message) > 70 or not MESSAGE_RE.match(message):
            return False
        if not isinstance(nonce, int) or isinstance(nonce, bool) or nonce < 0:
            return False
        if not isinstance(signature, str) or not HEX128.match(signature):
            return False
        return True

    def _signing_payload(self, tx: Dict[str, Any]) -> bytes:
        body = {
            "message": tx["message"],
            "nonce": tx["nonce"],
            "sender": tx["sender"],
        }
        return json.dumps(body, sort_keys=True, separators=(", ", ": ")).encode("utf-8")

    def _verify_signature(self, tx: Dict[str, Any]) -> bool:
        try:
            verify_key = VerifyKey(bytes.fromhex(tx["sender"]))
            verify_key.verify(self._signing_payload(tx), bytes.fromhex(tx["signature"]))
            return True
        except (BadSignatureError, ValueError):
            return False

    def validate_transaction(self, tx: Dict[str, Any]) -> bool:
        if not self._validate_fields(tx):
            return False
        if not self._verify_signature(tx):
            return False
        with self.lock:
            if tx["nonce"] != self.confirmed_nonce(tx["sender"]):
                return False
            if (tx["sender"], tx["nonce"]) in self.pool:
                return False
        return True

    def _forward_transaction(self, tx: Dict[str, Any]) -> None:
        message = {"type": "transaction", "payload": tx}
        for host, port in self.remote_peers:
            if (host, port) in self.crashed:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(2.0)
                sock.connect((host, port))
                send_framed(sock, message)
                recv_bool(sock)
            except (ConnectionError, OSError, json.JSONDecodeError, struct.error, ValueError):
                pass
            finally:
                try:
                    sock.close()
                except OSError:
                    pass

    def add_transaction(self, tx: Dict[str, Any], propagate: bool = True) -> bool:
        if not self.validate_transaction(tx):
            return False
        with self.lock:
            self.pool[(tx["sender"], tx["nonce"])] = dict(tx)
            self.logged_txs.add((tx["sender"], tx["nonce"]))
        self._log_transaction(tx)
        if propagate:
            threading.Thread(
                target=self._forward_transaction, args=(tx,), daemon=True
            ).start()
        if not self.in_consensus:
            self.consensus_event.set()
        return True

    def _log_transaction(self, tx: Dict[str, Any]) -> None:
        wrapped = {"type": "transaction", "payload": tx}
        with self._stdout_lock:
            print(canonical_json(wrapped), flush=True)

    def _log_block(self, block: Dict[str, Any]) -> None:
        with self._stdout_lock:
            print(canonical_json(block), flush=True)

    def create_proposal(self) -> Dict[str, Any]:
        with self.lock:
            txs = [self.pool[k] for k in sorted(self.pool.keys())]
            block = {
                "index": len(self.chain) + 1,
                "transactions": txs,
                "previous_hash": self.chain[-1]["current_hash"],
            }
            block["current_hash"] = compute_block_hash(block)
            return block

    def _io_lock(self, sock: socket.socket) -> threading.Lock:
        with self.sock_lock:
            if id(sock) not in self.sock_io_locks:
                self.sock_io_locks[id(sock)] = threading.Lock()
            return self.sock_io_locks[id(sock)]

    def _register_peer_sock(self, peer: Tuple[str, int], sock: socket.socket) -> None:
        with self.sock_lock:
            old = self.peer_socks.get(peer)
            if old is not None and old is not sock:
                try:
                    old.close()
                except OSError:
                    pass
                self.sock_peers.pop(id(old), None)
                self.values_waiters.pop(id(old), None)
                self.sock_io_locks.pop(id(old), None)
            self.peer_socks[peer] = sock
            self.sock_peers[id(sock)] = peer
            if id(sock) not in self.sock_io_locks:
                self.sock_io_locks[id(sock)] = threading.Lock()

    def _remove_peer_sock(self, sock: socket.socket) -> None:
        with self.sock_lock:
            peer = self.sock_peers.pop(id(sock), None)
            if peer is not None and self.peer_socks.get(peer) is sock:
                del self.peer_socks[peer]
            self.values_waiters.pop(id(sock), None)
            self.sock_io_locks.pop(id(sock), None)

    def _get_peer_sock(self, peer: Tuple[str, int]) -> Optional[socket.socket]:
        with self.sock_lock:
            if peer in self.crashed:
                return None
            return self.peer_socks.get(peer)

    def _mark_peer_crashed(self, peer: Tuple[str, int]) -> None:
        with self.sock_lock:
            self.crashed.add(peer)
            sock = self.peer_socks.pop(peer, None)
            if sock is not None:
                self.sock_peers.pop(id(sock), None)
                self.values_waiters.pop(id(sock), None)
                self.sock_io_locks.pop(id(sock), None)
                try:
                    sock.close()
                except OSError:
                    pass

    def _record_proposals(self, blocks: List[Any]) -> None:
        if not isinstance(blocks, list):
            return
        with self.round_proposals_lock:
            for block in blocks:
                if isinstance(block, dict) and "current_hash" in block:
                    self.round_proposals[block["current_hash"]] = block

    def _values_response_payload(self) -> List[Any]:
        if self.current_proposal is not None:
            return [self.current_proposal]
        return []

    def _should_join_round(self, blocks: List[Any]) -> bool:
        if not isinstance(blocks, list):
            return False
        with self.lock:
            next_index = len(self.chain) + 1
            pool_nonempty = bool(self.pool)
        relevant = [
            b
            for b in blocks
            if isinstance(b, dict) and b.get("index") == next_index
        ]
        if not relevant:
            return False
        if any(b.get("transactions") for b in relevant):
            return True
        return pool_nonempty

    def _handle_values(self, sock: socket.socket, payload: Any) -> None:
        blocks = payload if isinstance(payload, list) else []
        self._record_proposals(blocks)
        
        with self.sock_lock:
            waiter = self.values_waiters.get(id(sock))
            
        if waiter is not None:
            # This completely breaks the infinite ping-pong deadlock.
            waiter.put(blocks)
        else:
            # We received a request. Send our proposal back.
            response = self._values_response_payload()
            try:
                send_framed(sock, {"type": "values", "payload": response})
            except Exception:
                pass
                
            if not self.in_consensus and self._should_join_round(blocks):
                self.consensus_event.set()

    def handle_connection(self, sock: socket.socket, is_peer_link: bool) -> None:
        lock = self._io_lock(sock)
        try:
            while self.running:
                msg = recv_framed(sock)
                with lock:
                    msg_type = msg.get("type")
                    payload = msg.get("payload")
                    if msg_type == "transaction":
                        accepted = self.add_transaction(
                            payload, propagate=not is_peer_link
                        )
                        send_bool(sock, accepted)
                    elif msg_type == "values":
                        self._handle_values(sock, payload)
        except (ConnectionError, OSError, json.JSONDecodeError, struct.error, ValueError):
            pass
        finally:
            self._remove_peer_sock(sock)
            try:
                sock.close()
            except OSError:
                pass

    def accept_loop(self) -> None:
        while self.running:
            try:
                conn, _addr = self.server_sock.accept()
            except OSError:
                break
            threading.Thread(
                target=self.handle_connection,
                args=(conn, False),
                daemon=True,
            ).start()

    def connect_loop(self) -> None:
        while self.running:
            for peer in self.remote_peers:
                if peer in self.crashed:
                    continue
                # Every node must  establish a dedicated connection to every other node
                if self._get_peer_sock(peer) is not None:
                    continue
                host, port = peer
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    sock.connect((host, port))
                    self._register_peer_sock(peer, sock)
                    threading.Thread(
                        target=self.handle_connection,
                        args=(sock, True),
                        daemon=True,
                    ).start()
                except OSError:
                    try:
                        sock.close()
                    except OSError:
                        pass
            threading.Event().wait(0.2)

    def _exchange_with_peer(self, peer: Tuple[str, int], proposal: Dict[str, Any]) -> None:
        sock = self._get_peer_sock(peer)
        if sock is None:
            return
        waiter: "queue.Queue[List[Any]]" = queue.Queue(maxsize=1)
        lock = self._io_lock(sock)
        with self.sock_lock:
            self.values_waiters[id(sock)] = waiter
        try:
            with lock:
                send_framed(sock, {"type": "values", "payload": [proposal]})
            blocks = waiter.get(timeout=2.0)
            self._record_proposals(blocks)
        except queue.Empty:
            self._mark_peer_crashed(peer)
        except (ConnectionError, OSError, json.JSONDecodeError, struct.error, ValueError):
            self._mark_peer_crashed(peer)
        finally:
            with self.sock_lock:
                self.values_waiters.pop(id(sock), None)

    def _decide_block(self) -> Optional[Dict[str, Any]]:
        with self.round_proposals_lock:
            proposals = list(self.round_proposals.values())
        if not proposals:
            return None
        non_empty = [b for b in proposals if b.get("transactions")]
        if not non_empty:
            return None
        return min(non_empty, key=lambda b: b["current_hash"])

    def _commit_block(self, block: Dict[str, Any]) -> bool:
        txs_to_log: List[Dict[str, Any]] = []
        with self.lock:
            if block["previous_hash"] != self.chain[-1]["current_hash"]:
                return False
            if block["index"] != len(self.chain) + 1:
                return False
            if compute_block_hash(block) != block["current_hash"]:
                return False
            self.chain.append(block)
            for tx in block["transactions"]:
                sender = tx["sender"]
                key = (sender, tx["nonce"])
                if key not in self.logged_txs:
                    self.logged_txs.add(key)
                    txs_to_log.append(dict(tx))
                self.sender_nonces[sender] = tx["nonce"] + 1
                self.pool.pop(key, None)
                
            # Prevents deleting future valid nonces if they somehow got queued up
            stale = [
                key
                for key in self.pool
                if key[1] < self.confirmed_nonce(key[0])
            ]
            for key in stale:
                del self.pool[key]
                
        for tx in txs_to_log:
            self._log_transaction(tx)
        self._log_block(block)
        return True

    def run_consensus_round(self) -> None:
        with self.consensus_lock:
            if self.in_consensus:
                return
            self.in_consensus = True
            proposal = self.create_proposal()
            self.current_proposal = proposal
            with self.round_proposals_lock:
                self.round_proposals = {proposal["current_hash"]: proposal}

        threads = [
            threading.Thread(
                target=self._exchange_with_peer, args=(peer, proposal), daemon=True
            )
            for peer in self.remote_peers
            if peer not in self.crashed
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        decided = self._decide_block()
        if decided is not None:
            self._commit_block(decided)

        with self.consensus_lock:
            self.in_consensus = False
            self.current_proposal = None

        with self.lock:
            if self.pool:
                self.consensus_event.set()

    def consensus_loop(self) -> None:
        while self.running:
            self.consensus_event.wait(timeout=0.2)
            if not self.running:
                break
            if self.consensus_event.is_set():
                self.consensus_event.clear()
                self.run_consensus_round()

    def start(self) -> None:
        threading.Thread(target=self.accept_loop, daemon=True).start()
        threading.Thread(target=self.connect_loop, daemon=True).start()
        threading.Thread(target=self.consensus_loop, daemon=True).start()
        try:
            while self.running:
                threading.Event().wait(1.0)
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            try:
                self.server_sock.close()
            except OSError:
                pass

def main() -> None:
    node = BlockchainNode(_port, sys.argv[2], _server_sock)
    node.start()

if __name__ == "__main__":
    main()