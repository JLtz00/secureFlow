"""Text and DOT visualizers for SecureFlow control-flow graphs."""

from __future__ import annotations

from analyzer.cfg_builder import CFG


def visualize_cfg(cfg: CFG) -> str:
    lines = [f"CFG {cfg.name}"]
    for block in cfg.blocks:
        lines.append(f"{block.name}:")
        for instruction in block.instructions:
            lines.append(f"  {instruction}")
        outgoing = [edge for edge in cfg.edges if edge.source == block.id]
        if outgoing:
            rendered = ", ".join(f"{edge.kind}->{cfg.blocks[edge.target].name}" for edge in outgoing)
            lines.append(f"  edges: {rendered}")
    return "\n".join(lines)


def cfg_to_dot(cfg: CFG) -> str:
    lines = [f'digraph "{cfg.name}" {{']
    for block in cfg.blocks:
        body = "\\l".join(str(instruction) for instruction in block.instructions) + "\\l"
        lines.append(f'  {block.name} [shape=box, label="{block.name}\\l{_escape(body)}"];')
    for edge in cfg.edges:
        lines.append(
            f'  B{edge.source} -> B{edge.target} [label="{edge.kind}"];'
        )
    lines.append("}")
    return "\n".join(lines)


def _escape(value: str) -> str:
    return value.replace('"', '\\"')
