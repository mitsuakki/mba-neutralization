import ast
import astor

class MCodeLexer(ast.NodeTransformer):
    def visit_Compare(self, node):
        self.generic_visit(node)

        print(node.ops)
        
if __name__ == "__main__":
    expr = ""
    
    