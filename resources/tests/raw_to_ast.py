import ast
import astor

# Le `PoC` si on peut appeler comme ça, n'est pas sur BinaryNinja ou autres tout simplement parce que j'ai l'impression que esReverse lag beaucoup en cette fin d'année.
# Adam est en bootload depuis ce matin sur la version demo, et les fichiers mettent 5min à s'ouvrir, les images crash et reload toute seules.

# Sur BinaryNinja ce serait techniquement plus rapide car ici on parse en AST sauf que le microcode est déjà représenté par des arbres
# Ca nous retirerait une couche importante dans la deobfuscation des MBAs

# Après plein de recherches, que Boris, l'auteur de d810 à lui aussi du endurer
# Il se trouve qu'il n'y a pas meilleur que la representation du microcode en AST pour le manipuler
# L'IA est aussi une solution, bien que l'IA liée à la sécurité en déplaît beaucoup je pense que c'est une piste à explorer (cf NeoReduce)

# Le problème de la solution actuelle est que chaque simplification induit une fonction à coder
# Plus le deobfuscateur se voudra large, plus il y aura de fonction à coder / appeler et la complexité suivra...
# Il faudrait pouvoir lancer la deobfuscation de chaque patterne sur un thread dédié, je m'explique

# (Attention, pire exemple de la planète en vu)

# Le MBA suivant: `((x ^ 1) + (x & 1))` se décompose en deux patternes
# Le premier patterne -> (x ^ 1)
# Le second -> (x & 1)

# On aurait un thread pour gérer le premier et un autre pour le second
# Et ceci recursivement.... opti ? je sais pas il faut tester xD

class SimplifyNegation(ast.NodeTransformer):
    def visit_BinOp(self, node):
        self.generic_visit(node)

        # On recherche le patterne: `-a-1`
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Sub):
            left = node.left # -a
            right = node.right # 1

            # Verifie si l'enfant gauche est égale à une variable de valeur `-a`
            if isinstance(left, ast.UnaryOp) and isinstance(left.op, ast.USub) and isinstance(left.operand, ast.Name):
                a = left.operand

                # Verifie si l'enfant droit est une constante de valeur `1`
                if isinstance(right, ast.Constant) and right.value == 1:
                    # Remplace par `~a`
                    return ast.UnaryOp(op=ast.Invert(), operand=a)

        return node

# Peut-être que pour devenir plus générique je devrais faire une fonction pour simplifier `(x ^ 1)` et une autre pour `(x & 1)`
# Cela limiterai la redondance de code entre par exemple un MBA: `((x ^ 1) + (x & 1))` et un autre: `((x ^ 1)) - (x | y))`
# On remarquerait une simplification déjà connue et codée `(x ^ 1)` ce qui permettrait d'additioner en quelques sortes les patternes connus
# Dans le but de deobfusquer de nouveaux patternes qui consistent après analyse en une simple concaténation de patterne déjà connus
# Cela éviterait la redondance de code au sein du projet...

class SimplifyAddition(ast.NodeTransformer):
    def visit_BinOp(self, node):
        self.generic_visit(node)

        # On recherche le patterne: `((x ^ 1) + (x & 1))`
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = node.left # (x ^ 1)
            right = node.right # (x & 1)

            # Verifie si l'enfant gauche est égal à (x ^ 1)
            # On verifie d'abord que l'operateur est un XOR, puis que la gauche est une variable
            if isinstance(left, ast.BinOp) and isinstance(left.op, ast.BitXor) and isinstance(left.left, ast.Name):
                # Ensuite que la droite est une constante de valeur `1`
                if isinstance (left.right, ast.Constant) and left.right.value == 1:
                    xl = left.left # On stock Xl

            # Verifie si l'enfant droit est égal à (x & 1)
            # On verifie d'abord que l'operateur est un AND, puis que la gauche est une variable
            if isinstance(right, ast.BinOp) and isinstance(right.op, ast.BitAnd) and isinstance(right.left, ast.Name):
                # Ensuite que la droite est une constante de valeur `1`
                if isinstance (right.right, ast.Constant) and right.right.value == 1:
                    xr = right.left # On stock Xr
            
            # Nous avons récupéré X à gauche et à droite
            # Vérifions qu'ils aient la même valeur 
            if xl.id == xr.id:
                # On remplace le patterne recherché, par celui simplifié `(x + 1)`
                return ast.BinOp(left=xl, op=ast.Add(), right=ast.Constant(value=1))
        return node

# Exemples
if __name__ == "__main__":
    mba1 = "-a-1"
    tree = ast.parse(mba1, mode="eval")
    optz  = SimplifyNegation()
    print(f"Expression MBA n°1 : {mba1}")
    print("Expression simplifiée : " + ast.unparse(ast.fix_missing_locations(optz.visit(tree))))
    
    print("\n")

    mba2 = "((x ^ 1) + (x & 1))"
    tree = ast.parse(mba2, mode="eval")
    optz  = SimplifyNegation()
    print(f"Expression MBA n°1 : {mba1}")
    print("Expression simplifiée : " + ast.unparse(ast.fix_missing_locations(optz.visit(tree))))