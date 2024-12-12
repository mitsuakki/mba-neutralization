from binaryninja import *

# This function simplifies microinstructions patterns that look like
# either: (x & 1) | (y & 1) ==> (x | y) & 1
# or:     (x & 1) ^ (y & 1) ==> (x ^ y) & 1
def simplify(il: LowLevelILInstruction):
    # Only applies to OR / XOR instructions
    if il.operation not in [LowLevelILOperation.LLIL_OR, LowLevelILOperation.LLIL_XOR]:
        return False

    # Only applies when the operands are results of other instructions
    if not isinstance(il.left, LowLevelILInstruction) or not isinstance(il.right, LowLevelILInstruction):
        return False

    # Check if the left operand has an AND with 1
    left_operand = il.left
    if left_operand.operation == LowLevelILOperation.LLIL_AND and left_operand.right.value == 1:
        left_res = left_operand.left
    else:
        return False

    # Check if the right operand has an AND with 1
    right_operand = il.right
    if right_operand.operation == LowLevelILOperation.LLIL_AND and right_operand.right.value == 1:
        right_res = right_operand.left
    else:
        return False

    # If we get here, then the pattern matched
    # Move the logical operation (OR or XOR) to the left-hand side
    new_il = il.llil.function.no_ret(il.operation, left_res, right_res)

    # Change the top-level instruction to AND, and set the right-hand side to 1
    il.operation = LowLevelILOperation.LLIL_AND
    il.left = new_il
    il.right = il.llil.const(1, 1)

    log_info("Pattern matched and optimized")
    return True

def run(bv):
    for func in bv.functions:
        for block in func.low_level_il:
            for il in block:
                simplify(il)

PluginCommand.register("eShard\\MBA neutralization", "Neutralize MBA", run(bv))