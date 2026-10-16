pragma circom 2.0.0;

template IsZero() {
    signal input in;
    signal output out;
    signal inverse;

    inverse <-- in != 0 ? 1 / in : 0;
    out <== -in * inverse + 1;
    in * out === 0;
}

template Smoke() {
    signal input a;
    signal input b;
    signal output product;
    signal output aIsZero;
    signal output bIsZero;
    signal inverse;

    product <== a * b;
    inverse <-- a != 0 ? 1 / a : 0;
    aIsZero <== 1 - a * inverse;
    a * aIsZero === 0;

    component zero = IsZero();
    zero.in <== b;
    bIsZero <== zero.out;
}

component main = Smoke();
