"""In-memory Multi-Account Session Token Management.

CRITICAL SECURITY RULES:
1. Tokens and API keys for connected Cloudflare accounts are stored only in-memory
   in bytearray buffers during runtime.
2. Upon disconnect, the memory buffers for accounts are explicitly zeroed (overwritten with null bytes).
3. Persistent profiles are stored in 'config.json' (strictly ignored by .gitignore to prevent leaks to GitHub).
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
import gc


class AccountSession:
    """Represents a single authenticated Cloudflare account in-memory."""

    def __init__(
        self,
        account_id: str,
        label: str,
        token: str = "",
        user_info: Optional[str] = None,
        auth_method: str = "token",
        global_api_key: Optional[str] = None,
        email: Optional[str] = None,
    ):
        self.account_id: str = account_id
        self.label: str = label
        self.auth_method: str = auth_method or "token"
        self._token_buffer: Optional[bytearray] = (
            bytearray(token.strip().encode("utf-8")) if token and token.strip() else None
        )
        self._key_buffer: Optional[bytearray] = (
            bytearray(global_api_key.strip().encode("utf-8"))
            if global_api_key and global_api_key.strip()
            else None
        )
        self.email: Optional[str] = email.strip() if email and email.strip() else None
        self.connected_at: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.user_info: Optional[str] = user_info or self.email
        self.zones: List[Any] = []

    def get_token(self) -> Optional[str]:
        if self._token_buffer and len(self._token_buffer) > 0:
            return self._token_buffer.decode("utf-8")
        return None

    def get_global_api_key(self) -> Optional[str]:
        if self._key_buffer and len(self._key_buffer) > 0:
            return self._key_buffer.decode("utf-8")
        return None

    def get_auth_headers(self) -> Dict[str, str]:
        """Generates authentication headers according to account's auth_method."""
        if self.auth_method == "key":
            key = self.get_global_api_key()
            if not key or not self.email:
                raise ValueError("Global API Key dan Email wajib terdaftar.")
            return {
                "X-Auth-Key": key,
                "X-Auth-Email": self.email,
            }
        else:
            tok = self.get_token()
            if not tok:
                raise ValueError("API Token tidak terdaftar.")
            return {
                "Authorization": f"Bearer {tok}",
            }

    def clear(self):
        """Zeroes bytearrays and removes references."""
        if self._token_buffer is not None:
            for i in range(len(self._token_buffer)):
                self._token_buffer[i] = 0
            self._token_buffer = None
        if self._key_buffer is not None:
            for i in range(len(self._key_buffer)):
                self._key_buffer[i] = 0
            self._key_buffer = None
        self.zones.clear()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "label": self.label,
            "connected_at": self.connected_at,
            "user_info": self.user_info or self.email or "-",
            "auth_method": self.auth_method,
            "zones_count": len(self.zones),
        }


class MultiAccountSessionManager:
    """Manages multiple in-memory Cloudflare account sessions simultaneously."""

    def __init__(self):
        self._accounts: Dict[str, AccountSession] = {}
        self._active_id: Optional[str] = None
        self._zone_to_account: Dict[str, str] = {}  # O(1) reverse lookup cache

    @property
    def is_connected(self) -> bool:
        return self._active_id is not None and self._active_id in self._accounts

    @property
    def account_count(self) -> int:
        return len(self._accounts)

    @property
    def active_account(self) -> Optional[AccountSession]:
        if self._active_id and self._active_id in self._accounts:
            return self._accounts[self._active_id]
        return None

    @property
    def active_id(self) -> Optional[str]:
        return self._active_id

    @property
    def last_connected_at(self) -> Optional[str]:
        if self.active_account:
            return self.active_account.connected_at
        return None

    def add_account(
        self,
        label: str,
        token: str = "",
        user_info: Optional[str] = None,
        auth_method: str = "token",
        global_api_key: Optional[str] = None,
        email: Optional[str] = None,
    ) -> str:
        """Adds a new Cloudflare account session in-memory."""
        if auth_method == "key":
            if not global_api_key or not global_api_key.strip():
                raise ValueError("Global API Key tidak boleh kosong.")
            if not email or not email.strip():
                raise ValueError("Email akun Cloudflare tidak boleh kosong.")
        else:
            if not token or not token.strip():
                raise ValueError("Token tidak boleh kosong.")

        existing_labels = {acc.label.lower() for acc in self._accounts.values()}
        raw_label = label.strip() if label and label.strip() else ""

        if not raw_label:
            idx = 1
            while f"akun cf #{idx}".lower() in existing_labels:
                idx += 1
            clean_label = f"Akun CF #{idx}"
        else:
            clean_label = raw_label
            if clean_label.lower() in existing_labels:
                suffix = 2
                candidate = f"{clean_label} ({suffix})"
                while candidate.lower() in existing_labels:
                    suffix += 1
                    candidate = f"{clean_label} ({suffix})"
                clean_label = candidate

        account_id = f"acc_{uuid.uuid4().hex[:8]}"
        session = AccountSession(
            account_id=account_id,
            label=clean_label,
            token=token,
            user_info=user_info,
            auth_method=auth_method,
            global_api_key=global_api_key,
            email=email,
        )
        self._accounts[account_id] = session

        # Automatically make active if first account
        if not self._active_id or self._active_id not in self._accounts:
            self._active_id = account_id

        return account_id

    def get_account(self, account_id: str) -> Optional[AccountSession]:
        """Gets AccountSession by account_id."""
        return self._accounts.get(account_id)

    def set_token(self, token: str, label: str = "Akun Utama", user_info: Optional[str] = None) -> str:
        """Legacy helper for backward compatibility."""
        return self.add_account(label, token, user_info)

    def switch_account(self, account_id: str) -> None:
        """Switches the active Cloudflare account."""
        if account_id in self._accounts:
            self._active_id = account_id
        else:
            raise KeyError(f"Akun ID '{account_id}' tidak ditemukan dalam sesi.")

    def get_token(self) -> Optional[str]:
        """Gets active account token."""
        if self.active_account:
            return self.active_account.get_token()
        return None

    def get_token_for(self, account_id: str) -> Optional[str]:
        """Gets token for a specific account."""
        if account_id in self._accounts:
            return self._accounts[account_id].get_token()
        return None

    def get_auth_headers_for(self, account_id: Optional[str] = None) -> Dict[str, str]:
        """Gets authentication headers dictionary for the specified or active account."""
        if account_id:
            # Check by account_id
            if account_id in self._accounts:
                return self._accounts[account_id].get_auth_headers()
            # Check by account label
            for acc in self._accounts.values():
                if acc.label.lower() == account_id.lower():
                    return acc.get_auth_headers()
            # Explicit account requested but not found/connected
            from src.utils.errors import AuthenticationError
            raise AuthenticationError(f"Akun Cloudflare '{account_id}' tidak terhubung dalam sesi aktif.")

        # Default fallback to active account
        if self._active_id and self._active_id in self._accounts:
            return self._accounts[self._active_id].get_auth_headers()

        token = self.get_token()
        if token:
            return {"Authorization": f"Bearer {token}"}
        from src.utils.errors import AuthenticationError
        raise AuthenticationError("Tidak ada akun Cloudflare aktif dalam sesi. Silakan hubungkan akun terlebih dahulu.")

    def register_zone_account(self, zone_id: str, account_id: str) -> None:
        """Indexes a zone_id to its owning account_id for O(1) instant lookup."""
        if zone_id and account_id:
            self._zone_to_account[zone_id] = account_id

    def find_account_id_for_zone(self, zone_id: str) -> Optional[str]:
        """Finds the account_id that owns the specified zone_id across all sessions.
        Uses O(1) memory index with O(N) fallback.
        """
        if not zone_id:
            return None
        if zone_id in self._zone_to_account:
            acc_id = self._zone_to_account[zone_id]
            if acc_id in self._accounts:
                return acc_id

        for acc in self._accounts.values():
            for z in acc.zones:
                zid = getattr(z, "id", None) or (z.get("id") if isinstance(z, dict) else None)
                if zid == zone_id:
                    self._zone_to_account[zone_id] = acc.account_id
                    return acc.account_id
        return None

    def get_account_by_label(self, label: str) -> Optional[AccountSession]:
        for acc in self._accounts.values():
            if acc.label.lower() == label.lower():
                return acc
        return None

    def remove_account(self, account_id: str) -> None:
        """Removes and zeroes token for a single account."""
        if account_id in self._accounts:
            self._accounts[account_id].clear()
            del self._accounts[account_id]
            self._zone_to_account = {k: v for k, v in self._zone_to_account.items() if v != account_id}
            if self._active_id == account_id:
                # Switch active account to another one if exists
                self._active_id = next(iter(self._accounts.keys()), None)
            gc.collect()

    def disconnect_all(self) -> None:
        """Disconnects and zeroes memory for all accounts."""
        for acc in list(self._accounts.values()):
            acc.clear()
        self._accounts.clear()
        self._zone_to_account.clear()
        self._active_id = None
        gc.collect()

    def disconnect(self) -> None:
        """Alias for disconnect_all."""
        self.disconnect_all()

    def clear_token(self) -> None:
        """Alias for disconnect_all for backwards compatibility."""
        self.disconnect_all()

    def get_all_accounts(self) -> List[AccountSession]:
        return list(self._accounts.values())


# Global active multi-account session manager instance
active_session = MultiAccountSessionManager()
