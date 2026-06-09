from analyzer.cfg_builder import build_cfg
from analyzer.cfg_visualizer import cfg_to_dot, visualize_cfg
from analyzer.ir import ConditionalJump, Jump
from analyzer.ir_generator import generate_ir
from analyzer.parser import parse


def test_leader_algorithm_builds_blocks_and_branch_edges():
    module = generate_ir(
        parse(
            """if user:
    query = user
else:
    query = "safe"
result = query
"""
        )
    )
    cfg = build_cfg(module.main.instructions)

    assert len(cfg.blocks) >= 4
    assert any(edge.kind == "true" for edge in cfg.edges)
    assert any(edge.kind == "false" for edge in cfg.edges)
    assert any(
        isinstance(instruction, ConditionalJump)
        for block in cfg.blocks
        for instruction in block.instructions
    )


def test_while_cfg_contains_back_edge():
    module = generate_ir(
        parse(
            """count = 0
while count < 3:
    count = count + 1
"""
        )
    )
    cfg = build_cfg(module.main.instructions)

    jump_blocks = [
        block
        for block in cfg.blocks
        if isinstance(block.instructions[-1], Jump)
    ]
    assert jump_blocks
    assert any(edge.target <= edge.source for edge in cfg.edges if edge.kind == "jump")


def test_cfg_visualizers_explain_blocks_and_edges():
    module = generate_ir(parse("value = input()\n"))
    cfg = build_cfg(module.main.instructions)

    text = visualize_cfg(cfg)
    dot = cfg_to_dot(cfg)

    assert "CFG <main>" in text
    assert "B0:" in text
    assert "digraph" in dot
    assert "B0" in dot



def test_returning_branch_does_not_create_unreachable_jump_block():
    module = generate_ir(
        parse(
            """def choose(value):
    if value:
        return value
    return "safe"
"""
        )
    )
    cfg = build_cfg(module.functions["choose"].instructions, "choose")

    assert not any(
        len(block.instructions) == 1 and isinstance(block.instructions[0], Jump)
        for block in cfg.blocks
    )
