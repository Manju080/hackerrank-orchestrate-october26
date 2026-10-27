"""Token usage and cost accounting utility.

Ensures transparent, non-fabricated recording of model calls, prompt tokens,
completion tokens, and financial costs.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time


@dataclass
class ModelPricing:
    """Pricing per million tokens in USD."""
    prompt_price_per_1m: float
    completion_price_per_1m: float


# Published pricing references (USD per million tokens)
DEFAULT_PRICING: Dict[str, ModelPricing] = {
    # Gemini Flash reference
    "gemini-2.0-flash": ModelPricing(prompt_price_per_1m=0.10, completion_price_per_1m=0.40),
    "gemini-1.5-flash": ModelPricing(prompt_price_per_1m=0.075, completion_price_per_1m=0.30),
    # Claude 3.5 Sonnet / Haiku reference
    "claude-3-5-sonnet": ModelPricing(prompt_price_per_1m=3.00, completion_price_per_1m=15.00),
    "claude-3-5-haiku": ModelPricing(prompt_price_per_1m=0.80, completion_price_per_1m=4.00),
    # OpenAI GPT-4o-mini reference
    "gpt-4o-mini": ModelPricing(prompt_price_per_1m=0.15, completion_price_per_1m=0.60),
}


@dataclass
class CallRecord:
    timestamp: float
    provider: str
    model: str
    case_id: Optional[str]
    task_name: str
    input_tokens: int
    output_tokens: int
    estimated_cost: float


class TokenTracker:
    """Singleton-style or instantiable usage tracker."""

    def __init__(self, pricing_table: Optional[Dict[str, ModelPricing]] = None):
        self.pricing_table = pricing_table or DEFAULT_PRICING
        self.calls: List[CallRecord] = []

    def record_call(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        case_id: Optional[str] = None,
        task_name: str = "general",
    ) -> CallRecord:
        """Record an observed model call with exact token metrics."""
        pricing = self.pricing_table.get(model, ModelPricing(0.0, 0.0))
        input_cost = (input_tokens / 1_000_000.0) * pricing.prompt_price_per_1m
        output_cost = (output_tokens / 1_000_000.0) * pricing.completion_price_per_1m
        total_cost = input_cost + output_cost

        record = CallRecord(
            timestamp=time.time(),
            provider=provider,
            model=model,
            case_id=case_id,
            task_name=task_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost=total_cost,
        )
        self.calls.append(record)
        return record

    def get_summary(self, total_cases: int = 518) -> Dict[str, any]:
        """Produce full accounting summary."""
        total_calls = len(self.calls)
        total_input_tokens = sum(c.input_tokens for c in self.calls)
        total_output_tokens = sum(c.output_tokens for c in self.calls)
        total_tokens = total_input_tokens + total_output_tokens
        total_cost = sum(c.estimated_cost for c in self.calls)

        by_model: Dict[str, Dict[str, any]] = {}
        for c in self.calls:
            if c.model not in by_model:
                by_model[c.model] = {
                    "provider": c.provider,
                    "calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "cost": 0.0,
                }
            bm = by_model[c.model]
            bm["calls"] += 1
            bm["input_tokens"] += c.input_tokens
            bm["output_tokens"] += c.output_tokens
            bm["cost"] += c.estimated_cost

        avg_tokens_per_req = (total_tokens / total_cases) if total_cases > 0 else 0.0
        avg_cost_per_req = (total_cost / total_cases) if total_cases > 0 else 0.0

        return {
            "total_calls": total_calls,
            "total_input_tokens": total_input_tokens,
            "total_output_tokens": total_output_tokens,
            "total_tokens": total_tokens,
            "total_cost": total_cost,
            "average_tokens_per_request": avg_tokens_per_req,
            "average_cost_per_request": avg_cost_per_req,
            "by_model": by_model,
        }

    def generate_markdown_report(self, total_cases: int = 518) -> str:
        """Format usage as a compliant Markdown report for evaluation/usage_report.md."""
        summary = self.get_summary(total_cases=total_cases)
        lines = [
            "# Model Usage and Cost Report",
            "",
            "## Summary",
            f"- **Total Model Calls:** {summary['total_calls']}",
            f"- **Total Input Tokens:** {summary['total_input_tokens']:,}",
            f"- **Total Output Tokens:** {summary['total_output_tokens']:,}",
            f"- **Total Tokens:** {summary['total_tokens']:,}",
            f"- **Average Tokens Per Request (over {total_cases} requests):** {summary['average_tokens_per_request']:.2f}",
            f"- **Total Estimated Cost:** ${summary['total_cost']:.4f}",
            f"- **Average Cost Per Request:** ${summary['average_cost_per_request']:.6f}",
            "",
            "## Per-Model Breakdown",
            "| Model | Provider | Calls | Input Tokens | Output Tokens | Total Cost |",
            "| :--- | :--- | :---: | :---: | :---: | :---: |",
        ]
        if not summary["by_model"]:
            lines.append("| None | None | 0 | 0 | 0 | $0.0000 |")
        else:
            for model, data in summary["by_model"].items():
                lines.append(
                    f"| {model} | {data['provider']} | {data['calls']} | "
                    f"{data['input_tokens']:,} | {data['output_tokens']:,} | ${data['cost']:.4f} |"
                )
        lines.append("")
        return "\n".join(lines)


# Global default tracker
tracker = TokenTracker()
