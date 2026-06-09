"""Control-flow graph construction using the leader algorithm."""

from __future__ import annotations

from dataclasses import dataclass, field

from analyzer.ir import ConditionalJump, Instruction, Jump, Label, Return


@dataclass
class BasicBlock:
    id: int
    instructions: list[Instruction] = field(default_factory=list)

    @property
    def name(self) -> str:
        return f"B{self.id}"


@dataclass(frozen=True)
class Edge:
    source: int
    target: int
    kind: str


@dataclass
class CFG:
    name: str
    blocks: list[BasicBlock] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    entry: int | None = None

    def successors(self, block_id: int) -> list[BasicBlock]:
        targets = {edge.target for edge in self.edges if edge.source == block_id}
        return [block for block in self.blocks if block.id in targets]


class CFGBuilder:
    def build(self, instructions: list[Instruction], name: str = "<main>") -> CFG:
        cfg = CFG(name=name)
        if not instructions:
            return cfg

        label_indices = {
            instruction.name: index
            for index, instruction in enumerate(instructions)
            if isinstance(instruction, Label)
        }
        leaders = {0}
        for index, instruction in enumerate(instructions):
            if isinstance(instruction, Label):
                leaders.add(index)
            if isinstance(instruction, (Jump, ConditionalJump, Return)) and index + 1 < len(instructions):
                leaders.add(index + 1)
            if isinstance(instruction, Jump) and instruction.target in label_indices:
                leaders.add(label_indices[instruction.target])
            if isinstance(instruction, ConditionalJump):
                if instruction.true_target in label_indices:
                    leaders.add(label_indices[instruction.true_target])
                if instruction.false_target in label_indices:
                    leaders.add(label_indices[instruction.false_target])

        ordered = sorted(leaders)
        index_to_block: dict[int, int] = {}
        for block_id, start in enumerate(ordered):
            end = ordered[block_id + 1] if block_id + 1 < len(ordered) else len(instructions)
            block = BasicBlock(id=block_id, instructions=instructions[start:end])
            cfg.blocks.append(block)
            for instruction_index in range(start, end):
                index_to_block[instruction_index] = block_id

        cfg.entry = 0
        label_to_block = {
            label: index_to_block[index]
            for label, index in label_indices.items()
        }
        for position, block in enumerate(cfg.blocks):
            last = block.instructions[-1]
            if isinstance(last, Jump):
                self._add_edge(cfg, block.id, label_to_block[last.target], "jump")
            elif isinstance(last, ConditionalJump):
                self._add_edge(cfg, block.id, label_to_block[last.true_target], "true")
                self._add_edge(cfg, block.id, label_to_block[last.false_target], "false")
            elif isinstance(last, Return):
                continue
            elif position + 1 < len(cfg.blocks):
                self._add_edge(cfg, block.id, cfg.blocks[position + 1].id, "fallthrough")
        return cfg

    def _add_edge(self, cfg: CFG, source: int, target: int, kind: str) -> None:
        edge = Edge(source=source, target=target, kind=kind)
        if edge not in cfg.edges:
            cfg.edges.append(edge)


def build_cfg(instructions: list[Instruction], name: str = "<main>") -> CFG:
    return CFGBuilder().build(instructions, name)
