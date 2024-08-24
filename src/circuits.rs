use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef};

type F = ark_secp256k1::Fr;
type A = ark_secp256k1::Affine;

pub struct ECDSAVerificationCircuit {
    pub signature: Option<F>,
    pub hash: Option<F>,
    pub public_key: Option<A>,
}

impl ConstraintSynthesizer<F> for ECDSAVerificationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> ark_relations::r1cs::Result<()> {
        let signature = self.signature;
        let hash = self.hash;
        let public_key = self.public_key;

        let signature =
            signature.ok_or_else(|| ark_relations::r1cs::SynthesisError::AssignmentMissing)?;

        let hash = hash.ok_or_else(|| ark_relations::r1cs::SynthesisError::AssignmentMissing)?;

        let public_key =
            public_key.ok_or_else(|| ark_relations::r1cs::SynthesisError::AssignmentMissing)?;

        let signature_var =
            FpVar::new_witness(ark_relations::ns!(cs, "signature"), || Ok(signature))?;

        let hash_var = FpVar::new_witness(ark_relations::ns!(cs, "hash"), || Ok(hash))?;

        Ok(())
    }
}
