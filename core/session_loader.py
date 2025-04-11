"""
Session loader module for handling authentication sessions and credentials
"""

from typing import Dict, Optional
import json
from dataclasses import dataclass

@dataclass
class Session:
    """Represents an authentication session with either cookie or token."""
    user_id: str
    cookie: Optional[str] = None
    token: Optional[str] = None

    def get_headers(self) -> Dict[str, str]:
        """
        Generate request headers based on session type.
        
        Returns:
            Dict of headers to use for requests
        """
        headers = {
            'User-Agent': 'IDOR-BAC-Hunter/1.0',
            'Accept': '*/*'
        }
        
        if self.token:
            headers['Authorization'] = self.token
        
        return headers
    
    def get_cookies(self) -> Optional[Dict[str, str]]:
        """
        Parse and return cookies if present.
        
        Returns:
            Dict of cookies or None if using token auth
        """
        if not self.cookie:
            return None
            
        # Handle multiple cookies if present
        cookies = {}
        for cookie in self.cookie.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
        return cookies

class SessionManager:
    """Manages multiple user sessions for testing."""
    
    def __init__(self, config_path: str):
        """
        Initialize SessionManager with config file.
        
        Args:
            config_path: Path to sessions.json configuration file
        """
        self.sessions: Dict[str, Session] = {}
        self.load_config(config_path)
    
    def load_config(self, config_path: str) -> None:
        """
        Load and validate session configurations.
        
        Args:
            config_path: Path to sessions.json file
        
        Raises:
            ValueError: If config format is invalid
            FileNotFoundError: If config file doesn't exist
        """
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        for user_id, settings in config.items():
            if not isinstance(settings, dict):
                raise ValueError(f"Invalid configuration for user {user_id}")
                
            session = Session(
                user_id=user_id,
                cookie=settings.get('cookie'),
                token=settings.get('token')
            )
            
            if not session.cookie and not session.token:
                raise ValueError(f"User {user_id} must have either cookie or token")
                
            self.sessions[user_id] = session
    
    def get_session(self, user_id: str) -> Optional[Session]:
        """
        Get session for specified user.
        
        Args:
            user_id: ID of the user to get session for
            
        Returns:
            Session object if found, None otherwise
        """
        return self.sessions.get(user_id)
    
    def list_users(self) -> list:
        """Return list of configured user IDs."""
        return list(self.sessions.keys())
    
    def __len__(self) -> int:
        """Return number of configured sessions."""
        return len(self.sessions) 