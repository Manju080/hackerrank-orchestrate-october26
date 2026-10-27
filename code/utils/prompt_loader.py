"""Prompt loader utility for reading and formatting Markdown prompt templates."""

from pathlib import Path
from typing import Dict, Any
from code.config import PROMPTS_DIR


class PromptLoader:
    """Loads and formats Markdown prompts stored in code/prompts/."""

    def __init__(self, prompts_dir: Path = PROMPTS_DIR):
        self.prompts_dir = prompts_dir

    def load_prompt(self, filename: str) -> str:
        """Load raw prompt text from a Markdown file."""
        prompt_path = self.prompts_dir / filename
        if not prompt_path.exists():
            raise FileNotFoundError(f"Prompt file not found at: {prompt_path}")
        return prompt_path.read_text(encoding="utf-8")

    def render_prompt(self, filename: str, **kwargs: Any) -> str:
        """Load and substitute keyword parameters into the prompt template."""
        raw_text = self.load_prompt(filename)
        try:
            return raw_text.format(**kwargs)
        except KeyError as e:
            raise ValueError(f"Missing required prompt format variable {e} in {filename}")


# Global default prompt loader
prompt_loader = PromptLoader()
