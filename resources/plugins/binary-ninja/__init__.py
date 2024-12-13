from binaryninja import *

# This function simplifies microinstructions patterns that look like
# either: (x & 1) | (y & 1) ==> (x | y) & 1
# or:     (x & 1) ^ (y & 1) ==> (x ^ y) & 1
def simplify(il: LowLevelILInstruction):
    # Only applies to OR / XOR instructions
    if il.operation not in [LowLevelILOperation.LLIL_OR, LowLevelILOperation.LLIL_XOR]:
        print("False 1: " + str(il.operation))
        return False

    # Only applies when the operands are results of other instructions
    if not isinstance(il.left, LowLevelILInstruction) or not isinstance(il.right, LowLevelILInstruction):
        print("False 2")
        return False

    # Check if the left operand has an AND with 1
    left_operand = il.left
    if left_operand.operation == LowLevelILOperation.LLIL_AND and left_operand.right.value == 1:
        left_res = left_operand.left
    else:
        print("False 3")
        return False

    # Check if the right operand has an AND with 1
    right_operand = il.right
    if right_operand.operation == LowLevelILOperation.LLIL_AND and right_operand.right.value == 1:
        right_res = right_operand.left
    else:
        print("False 4")
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

from binaryninja import PluginCommand, LowLevelILOperation, LowLevelILInstruction, log_info

def simplify_expression(il: LowLevelILInstruction):
    if il.operation == LowLevelILOperation.LLIL_AND:
        left = il.left
        right = il.right

        if left.operation == LowLevelILOperation.LLIL_AND and right.operation == LowLevelILOperation.LLIL_AND:
            left_left = left.left
            left_right = left.right
            right_left = right.left
            right_right = right.right

            if (left_left.operation == LowLevelILOperation.LLIL_CONST and left_left.constant == 0xFFFFFFFF and
                left_right.operation == LowLevelILOperation.LLIL_CONST and left_right.constant == 0xFFFFFFFF and
                right_left.operation == LowLevelILOperation.LLIL_CONST and right_left.constant == 0xFFFFFFFF and
                right_right.operation == LowLevelILOperation.LLIL_CONST and right_right.constant == 0xFFFFFFFF):
                
                # simplified_value = (((((((((left_left.constant & (~right_right.constant)) + 
                #                          (left_left.constant * 0xFFFFFFFF)) + 
                #                         ((~right_right.constant) * 0xFFFFFFFF)) + 
                #                        (left_left.constant | (~right_right.constant))) + 
                #                       0x7FFFFFFF) * 0x991F340F) + 
                #                     0x62250C86) * 0xC5BD3AEF) - 
                #                    0x625B0D1A)
                
                il.operation = LowLevelILOperation.LLIL_CONST
                il.constant = simplified_value
                log_info(f"Simplified expression at address: 0x{il.address:x}")

                return True
    return False

def analyze_function(bv):
    for func in bv.functions:
        for block in func.low_level_il:
            for il in block:
                simplify_expression(il)

PluginCommand.register("Sample Plugin\\SimplifySpecificExpression", "Simplify specific MIL expressions in the code", analyze_function)