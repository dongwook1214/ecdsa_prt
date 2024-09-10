use crate::gadgets::ecdsa::constraints::{
    ECDSAVerificationGadget, HashVar, ParametersVar, PublicKeyVar, SignatureVar,
    SignatureVerificationGadget,
};
use crate::gadgets::ecdsa::{Hash, Parameters, PublicKey, Signature};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{Boolean, CurveVar, EqGadget};
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use std::marker::PhantomData;

#[derive(Clone)]
pub struct ECDSACircuit<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    // constant
    pub g: Parameters<C>,
    pub modulus: C::BaseField,

    // statements
    pub pk: Option<PublicKey<C>>,
    pub hash: Option<Hash<C>>,

    // witness
    pub signature: Option<Signature<C>>,

    pub _curve_var: PhantomData<GG>,
}

impl<C, GG> ConstraintSynthesizer<C::BaseField> for ECDSACircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField,
{
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<C::BaseField>,
    ) -> Result<(), SynthesisError> {
        let g = ParametersVar::<C, GG>::new_constant(cs.clone(), self.g)?;
        let modulus = FpVar::new_constant(cs.clone(), self.modulus)?;
        // let modulus = FpVar::new_input(cs.clone(), || Ok(self.modulus))?;
        let pk = PublicKeyVar::<C, GG>::new_input(cs.clone(), || {
            self.pk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let hash = HashVar::<C::ScalarField, C::BaseField>::new_input(cs.clone(), || {
            self.hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let signature =
            SignatureVar::<C::ScalarField, C::BaseField>::new_witness(cs.clone(), || {
                self.signature.ok_or(SynthesisError::AssignmentMissing)
            })?;

        let result = ECDSAVerificationGadget::<C, GG>::verify(&g, &pk, &hash, &signature, modulus)?;
        result.enforce_equal(&Boolean::TRUE)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::circuits::ecdsa::ECDSACircuit;
    use crate::gadgets::ecdsa::{scalar_to_base, Hash, Parameters, SignatureScheme, ECDSA};
    use ark_bn254::Bn254;
    use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fq, Fr};
    use ark_ff::PrimeField;
    use ark_groth16::Groth16;
    use ark_r1cs_std::fields::nonnative::params::OptimizationType;
    use ark_r1cs_std::fields::nonnative::{AllocatedNonNativeFieldVar, NonNativeFieldVar};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
    use ark_std::{test_rng, UniformRand};
    use rand::{RngCore, SeedableRng};

    type C = EdwardsProjective;
    type GG = EdwardsVar;

    type MyECDSA = ECDSA<EdwardsProjective>;

    #[test]
    fn test_ecdsa_circuit() {
        let mut seed: u64 = 11;
        let rng = &mut rand::rngs::StdRng::seed_from_u64(seed);

        let g = MyECDSA::setup(rng).unwrap();
        let modulus = Fq::from_bigint(Fr::MODULUS).unwrap();
        let (secret_key, public_key) = MyECDSA::keygen(&g, rng).unwrap();
        let hash = Hash(Fr::rand(rng));
        let signature = MyECDSA::sign(&g, &secret_key, &hash, rng).unwrap();

        let circuit = ECDSACircuit::<C, GG> {
            g,
            modulus,
            pk: Some(public_key),
            hash: Some(hash),
            signature: Some(signature),
            _curve_var: std::marker::PhantomData,
        };

        let cs = ConstraintSystem::new_ref();

        circuit.generate_constraints(cs.clone()).unwrap();
        println!("number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_groth16_ecdsa_circuit() {
        let mut seed: u64 = 9;
        let rng = &mut rand::rngs::StdRng::seed_from_u64(seed);

        let g = MyECDSA::setup(rng).unwrap();
        let modulus = Fq::from_bigint(Fr::MODULUS).unwrap();
        let (secret_key, public_key) = MyECDSA::keygen(&g, rng).unwrap();
        let hash = Hash(Fr::rand(rng));
        let signature = MyECDSA::sign(&g, &secret_key, &hash, rng).unwrap();

        let circuit = ECDSACircuit::<C, GG> {
            g,
            modulus,
            pk: Some(public_key),
            hash: Some(hash.clone()),
            signature: Some(signature),
            _curve_var: std::marker::PhantomData,
        };

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        let limbs: Vec<Fq> = AllocatedNonNativeFieldVar::get_limbs_representations(
            &hash.0,
            OptimizationType::Constraints,
        )
        .unwrap();

        let verify_inputs = [vec![public_key.x, public_key.y], limbs].concat();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).unwrap();
        let res = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &verify_inputs, &proof).unwrap();

        assert!(res);
    }

    #[test]
    #[should_panic]
    fn fail_test_groth16_ecdsa_circuit() {
        let mut seed: u64 = 9;
        let rng = &mut rand::rngs::StdRng::seed_from_u64(seed);

        let g = MyECDSA::setup(rng).unwrap();
        let modulus = Fq::from_bigint(Fr::MODULUS).unwrap();
        let (secret_key, public_key) = MyECDSA::keygen(&g, rng).unwrap();
        let hash = Hash(Fr::rand(rng));
        let signature = MyECDSA::sign(&g, &secret_key, &hash, rng).unwrap();

        let circuit = ECDSACircuit::<C, GG> {
            g,
            modulus,
            pk: Some(public_key),
            hash: Some(hash.clone()),
            signature: Some(signature),
            _curve_var: std::marker::PhantomData,
        };

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng).unwrap();
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

        let limbs: Vec<Fq> = AllocatedNonNativeFieldVar::get_limbs_representations(
            &Fr::rand(rng),
            OptimizationType::Constraints,
        )
            .unwrap();

        let verify_inputs = [vec![public_key.x, public_key.y], limbs].concat();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, rng).unwrap();
        let res = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &verify_inputs, &proof).unwrap();

        assert!(res);
    }
}
