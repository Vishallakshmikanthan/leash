"""
shim/adapters/__init__.py - Agent adapter package.
"""
from shim.adapters.base import BaseAgentAdapter
from shim.adapters.claude_code import ClaudeCodeAdapter
from shim.adapters.generic import GenericJsonAdapter

__all__ = ["BaseAgentAdapter", "ClaudeCodeAdapter", "GenericJsonAdapter"]
