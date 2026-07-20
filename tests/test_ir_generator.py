from analyzer.ir import Assign, BinaryOp, BuildCollection, Call, ConditionalJump, Jump, Return
from analyzer.ir_generator import generate_ir
from analyzer.parser import parse


def test_generates_three_address_code_for_expression():
    module = generate_ir(parse("result = a + b * 3\n"))
    instructions = module.main.instructions

    assert isinstance(instructions[0], BinaryOp)
    assert instructions[0].operator == "*"
    assert isinstance(instructions[1], BinaryOp)
    assert instructions[1].operator == "+"
    assert instructions[1].right == instructions[0].target
    assert isinstance(instructions[2], Assign)
    assert instructions[2].target == "result"


def test_generates_call_and_assignment():
    module = generate_ir(parse('user = request.args.get("user")\n'))
    instructions = module.main.instructions

    assert isinstance(instructions[0], Call)
    assert instructions[0].function == "request.args.get"
    assert instructions[0].args == ['"user"']
    assert isinstance(instructions[1], Assign)
    assert instructions[1].value == instructions[0].target


def test_generates_tuple_for_parameterized_call():
    module = generate_ir(
        parse('cursor.execute("SELECT * FROM users WHERE id = ?", (user,))\n')
    )
    instructions = module.main.instructions

    assert isinstance(instructions[0], BuildCollection)
    assert instructions[0].kind == "tuple"
    assert instructions[0].elements == ["user"]
    assert isinstance(instructions[1], Call)
    assert instructions[1].args == ['"SELECT * FROM users WHERE id = ?"', instructions[0].target]


def test_generates_functions_separately_from_main():
    module = generate_ir(
        parse(
            """def build(user):
    query = "SELECT " + user
    return query

value = build(input())
"""
        )
    )

    assert "build" in module.functions
    assert module.functions["build"].params == ["user"]
    assert isinstance(module.functions["build"].instructions[-1], Return)
    assert any(isinstance(instruction, Call) for instruction in module.main.instructions)


def test_generates_control_flow_for_if_and_while():
    module = generate_ir(
        parse(
            """if user:
    query = user
else:
    query = "safe"

while query:
    query = ""
"""
        )
    )

    instructions = module.main.instructions

    assert sum(isinstance(item, ConditionalJump) for item in instructions) == 2
    assert sum(isinstance(item, Jump) for item in instructions) >= 2
