from py_ecc.bls12_381 import G1, G2, multiply, pairing, neg, add, curve_order

# 1. Setup
# generate 3 sk and 3 pk
# sign 1, 2, 3 * A and create S
# verify S with pairings

# auxiliary public point
A = multiply(G2, 1234)

m1 = 1
sk1 = 5566
pk1 = multiply(G1, sk1)
S1 = multiply(multiply(A, m1), sk1)
m2 = 2
sk2 = 5577
pk2 = multiply(G1, sk2)
S2 = multiply(multiply(A, m2), sk2)
m3 = 3
sk3 = 5588
pk3 = multiply(G1, sk3)
S3 = multiply(multiply(A, m3), sk3)

# assert(pairing(multiply(A, 1), pk1) == pairing(S1, G1))
# assert(pairing(multiply(A, 2), pk2) == pairing(S2, G1))
# assert(pairing(multiply(A, 3), pk3) == pairing(S3, G1))
print("pass setup phase")

# 2. Vanilla Rogue
# create new sk and pk
# hash message and sign
# aggregate public keys
# aggregate signatures
# verify aggS with pairings
#
# sha256("brozorec")
m = 0x741936751cf3c75753904bcf2d7a212e051d2dddc53f163c44d9fa6f17ec3be5
# m = 4
sk = 5698
pk = multiply(G1, sk)
H = multiply(A, m)
S = multiply(H, sk)
newK = add(pk, neg(pk1))
newK = add(newK, neg(pk2))
newK = add(newK, neg(pk3))
aggK = add(newK, pk1)
aggK = add(aggK, pk2)
aggK = add(aggK, pk3)

newS = add(S, neg(S1))
newS = add(newS, neg(S2))
newS = add(newS, neg(S3))
aggS = add(newS, S1)
aggS = add(aggS, S2)
aggS = add(aggS, S3)

# assert(pairing(H, aggK) == pairing(aggS, G1))
print("pass vanilla phase")
fS1 = multiply(S1, m)
fS2 = multiply(S2, m * pow(2, -1, curve_order))
fS3 = multiply(S3, m * pow(3, -1, curve_order))
print(fS3)
print(multiply(multiply(A, m), sk3))
aaS = add(S, add(fS1, add(fS2, fS3)))
aaK = add(pk, add(pk1, add(pk2, pk3)))
assert(pairing(H, aaK) == pairing(aaS, G1))

# 3. New proof
m = 4
H = multiply(A, m)
S = multiply(H, sk)
assert(pairing(H, pk) == pairing(S, G1))

# 3. Malleability
# create new_proof = H(m).inverse * 4 * aggS
# verify with pairings
# H = multiply(A, 4)
# ratio = pow(m, -1, curve_order) * 4 % curve_order
# proof = multiply(newS, ratio)

# assert(pairing(H, newK) == pairing(proof, G1))
