# vrf tests

https://github.com/coniks-sys/coniks-go
https://github.com/coniks-sys/coniks-java
https://github.com/facebook/akd
https://github.com/algorand/go-algorand/tree/master/crypto VRF impl
https://medium.com/witnet/announcing-our-verifiable-random-function-vrf-library-in-solidity-c847edf123f7 and https://www.npmjs.com/package/vrf-solidity

RFC https://datatracker.ietf.org/doc/html/rfc9381

SK: The secret key for the VRF. (Note: The secret key is also sometimes called a "private key".)
PK: The public key for the VRF.
alpha or alpha_string: The input to be hashed by the VRF.
beta or beta_string: The VRF hash output.
pi or pi_string: The VRF proof.
Prover: Holds the VRF secret key SK and public key PK.
Verifier: Holds the VRF public key PK.

The Prover hashes an input alpha using the VRF secret key SK to obtain a VRF hash output beta:

    beta = VRF_hash(SK, alpha)

The Prover also uses the secret key SK to construct a proof pi that beta is the correct hash output:

    pi = VRF_prove(SK, alpha)

The VRFs defined in this document allow anyone to deterministically obtain the VRF hash output beta directly from the proof value pi by using the function VRF_proof_to_hash:

    beta = VRF_proof_to_hash(pi)

Thus, for the VRFs defined in this document, VRF_hash is defined as

    VRF_hash(SK, alpha) = VRF_proof_to_hash(VRF_prove(SK, alpha))

beta, "VALID" = VRF_proof_to_hash(pi)


We should use https://pkg.go.dev/crypto/ed25519/internal/edwards25519 which is filippo.io/edwards25519 -> https://github.com/FiloSottile/edwards25519
coniks-go copied the files in https://github.com/coniks-sys/coniks-go/blob/master/crypto/internal/ed25519/edwards25519/

pad.LookupIndex() -> vrf, proof
merkeltree.Get(vrf)