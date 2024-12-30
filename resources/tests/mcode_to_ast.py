import ast
import astor

class MCodeLexer(ast.NodeTransformer):
    def visit_Compare(self, node):
        self.generic_visit(node)

        if len(node.op)