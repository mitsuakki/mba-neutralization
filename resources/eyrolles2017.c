int main() {
    int x = 0;
    int e = (x | 2);
    int mul1 = ((e & 728040545) * (e | 728040545));
    int mul2 = (e & (~728040545))*(~ e & 728040545);
    int mul = (mul1 + mul2 ) + 198791817;
    return mul *264282017 - 1538260777;
}