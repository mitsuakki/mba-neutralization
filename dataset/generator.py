import argparse
import pandas as pd

from z3 import *

class Generator(object):
    def __init__(self, nVars: int):
        self.nVars = nVars

    def generate(self):
        pass

class ExpressionGenerator(Generator):
    """
        Generate a Linear MBA expressions.
        Each terms in expression is the simpliest form of two boolean vars expression.
        We list those simpliest form as member variable expr.
    
        Attributes:
            nTerms:      The number of terms which is the simpliest boolean expression
            exprs:       Basic expressions which can deduce all other expressions. And we use -1 to represent constant.
            rules:       The truth of expressions in exprs
            indexes:     All possible combinations of expressions in exprs
    """

    def __init__(self, nVars: int, nTerms: int):
        super().__init__(nVars)
        self.nTerms = nTerms
        self.indexes = []

        # A bitwise expression En with n variables has 2^(2^n) different reduced Boolean expression
        self.exprs = [
            "x", "y", "-1", "~x", "~y", 
            "x & y", "~x & y", "x & ~y", "~(x & y)", 
            "x | y", "~x | y", "x | ~y", "~(x | y)",
            "x ^ y", "~x ^ y", "x ^ ~y", "~(x ^ y)"
        ]

        # Truth tables of self.exprs
        self.rules = {
            "x": [0, 0, 1, 1], "y": [0, 1, 0, 1]
        }

    def index_combine(self, start: int, tmp: list):
        """
            Recursively generate all possible combinations of non-repeating nTerms expressions in exprs.
            Store all possible combination in self.indexes.
        """

        if len(tmp) == self.nTerms:
            self.indexes.append(list(tmp))
            return

        for i in range(start, len(self.exprs)):
            tmp.append(i)
            self.index_combine(i + 1, tmp)
            tmp.pop()
            i += 10 ** (self.nVars - 2)
    
    def expression_generate():
        pass

    def generate(self):
        pass

# References:
#      - https://aclanthology.org/2020.findings-emnlp.56.pdf
#      - https://link.springer.com/chapter/10.1007/978-3-540-77535-5_5
#
# This script is a fork of the NeoReduce paper
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate MBA dataset")
    parser.add_argument("--numOfTerms", type=int, default=5, help="Number of terms")
    parser.add_argument("--numOfVars", type=int, default=2, help="Number of variables")

    args = parser.parse_args()
    if args.numOfVars >= 2:
        ge = ExpressionGenerator(nVars=args.numOfVars, nTerms=args.numOfTerms)
        ge.generate()

        df = pd.DataFrame(ge)
        origin = list(df[0])
        mba_confusion = list(data[1])

        x = BitVec('x', 32)
        y = BitVec('y', 32)
        z = BitVec('z', 32)

        count = 0
        for i in range(len(origin)):
            print("No.%d:" % i, end=' ')
            solve(eval(origin[i]) != eval(mba_confusion[i]))
            count += 1
        print("Number of test sample", count)

        df.to_csv("./dataset.csv", mode="a+", header=False, index=False)
    else:
        print("In order to have decent MBA we need at least 2 vars in the expression")