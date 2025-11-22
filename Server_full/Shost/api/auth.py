"""
Bearer-token authentication helpers for Shikra Host API.
Removes the need for per-request HMAC in this environment.
"""

from flask import request, jsonify
from functools import wraps
import hashlib
import time
import logging

from .simple_store import agent_store

logger = logging.getLogger(__name__)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def require_agent_auth(f):
    """Decorator to require bearer-token authentication for agent requests.
    Expects headers:
      - X-Agent-ID: <agent_id>
      - Authorization: Bearer <access_token>
    """

    @wraps(f)
    def _wrapped(*args, **kwargs):
        agent_id = request.headers.get('X-Agent-ID')
        auth = request.headers.get('Authorization', '')

        if not agent_id:
            return jsonify({'error': 'Missing X-Agent-ID header'}), 401

        agent = agent_store.get_agent(agent_id)
        if not agent:
            return jsonify({'error': 'Unknown agent'}), 401

        # Extract token - accept both "Bearer <token>" and raw token for compatibility
        if auth.startswith('Bearer '):
            token = auth.split(' ', 1)[1].strip()
        else:
            # Agent sent raw token without "Bearer" prefix - accept it
            token = auth.strip()
        
        if not token:
            return jsonify({'error': 'Missing bearer token'}), 401

        token_sha = agent.get('token_sha')
        token_expires = int(agent.get('token_expires', 0))

        if not token_sha:
            return jsonify({'error': 'No token provisioned for agent'}), 401

        if _hash_token(token) != token_sha:
            logger.warning(f"Bearer token mismatch for agent {agent_id}")
            return jsonify({'error': 'Unauthorized'}), 401

        now = int(time.time())
        if token_expires and now > token_expires:
            logger.info(f"Bearer token expired for agent {agent_id}")
            return jsonify({'error': 'Token expired'}), 401

        # Stamp last-seen
        agent_store.update_agent_last_seen(agent_id)
        # Attach agent_id for handlers
        request.agent_id = agent_id
        return f(*args, **kwargs)

    return _wrapped


__all__ = [
    'require_agent_auth',
    '_hash_token',
]
