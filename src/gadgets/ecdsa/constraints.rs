use crate::gadgets::ecdsa::{
    base_to_scalar, scalar_to_base, Hash, Parameters, PublicKey, Signature, SignatureScheme, ECDSA,
};
use ark_bn254::Fq;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::constraints::FqVar;
use ark_ff::{BigInt, Field, One, PrimeField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::nonnative::{AllocatedNonNativeFieldVar, NonNativeFieldVar};
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::{R1CSVar, ToBitsGadget};
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::marker::PhantomData;
use std::ops::{Mul, MulAssign, Sub};

pub trait SignatureVerificationGadget<C: SignatureScheme, ConstraintF: PrimeField> {
    type ParametersVar: AllocVar<C::Parameters, ConstraintF> + Clone;
    type ModulusVar: AllocVar<ConstraintF, ConstraintF> + Clone;
    type PublicKeyVar: AllocVar<C::PublicKey, ConstraintF> + Clone;
    type SignatureVar: AllocVar<C::Signature, ConstraintF> + Clone;
    type HashVar: AllocVar<C::Hash, ConstraintF> + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        hash: &Self::HashVar,
        signature: &Self::SignatureVar,
        modulus: FpVar<ConstraintF>,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

#[derive(Clone)]
pub struct ParametersVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    pub generator: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<Parameters<C>, C::BaseField> for ParametersVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GG::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        Ok(Self {
            generator,
            _curve: PhantomData,
        })
    }
}

#[derive(Clone)]
pub struct PublicKeyVar<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    pub public_key: GG,
    pub _curve: PhantomData<C>,
}

impl<C, GG> AllocVar<PublicKey<C>, C::BaseField> for PublicKeyVar<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<C::BaseField>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let public_key: GG = GG::new_variable(cs, f, mode)?;
        Ok(Self {
            public_key,
            _curve: PhantomData,
        })
    }
}

#[derive(Clone)]
pub struct SignatureVar<Fr: PrimeField, Fq: PrimeField> {
    pub r: NonNativeFieldVar<Fr, Fq>,
    pub s: NonNativeFieldVar<Fr, Fq>,
}

impl<C, Fr, Fq> AllocVar<Signature<C>, Fq> for SignatureVar<Fr, Fq>
where
    C: CurveGroup<ScalarField = Fr>,
    Fr: PrimeField,
    Fq: PrimeField,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().map(|s| Self {
            r: NonNativeFieldVar::new_variable(cs.clone(), || Ok(s.borrow().r), mode).unwrap(),
            s: NonNativeFieldVar::new_variable(cs, || Ok(s.borrow().s), mode).unwrap(),
        })
    }
}

#[derive(Clone)]
pub struct HashVar<Fr: PrimeField, Fq: PrimeField>(pub NonNativeFieldVar<Fr, Fq>);

impl<C, Fr, Fq> AllocVar<Hash<C>, Fq> for HashVar<Fr, Fq>
where
    C: CurveGroup<ScalarField = Fr>,
    Fq: PrimeField,
    Fr: PrimeField,
{
    fn new_variable<T: Borrow<Hash<C>>>(
        cs: impl Into<Namespace<Fq>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().map(|h| Self(NonNativeFieldVar::new_variable(cs, || Ok(h.borrow().0), mode).unwrap()))
    }
}

#[derive(Clone)]
pub struct ECDSAVerificationGadget<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    #[doc(hidden)]
    _curve: PhantomData<C>,
    _field: PhantomData<GG>,
}

impl<C, GG> SignatureVerificationGadget<ECDSA<C>, C::BaseField> for ECDSAVerificationGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField,
    C::BaseField: PrimeField,
{
    type ParametersVar = ParametersVar<C, GG>;
    type ModulusVar = FpVar<C::BaseField>;
    type PublicKeyVar = PublicKeyVar<C, GG>;
    type SignatureVar = SignatureVar<C::ScalarField, C::BaseField>;
    type HashVar = HashVar<C::ScalarField, C::BaseField>;

    /// R ?= (s⁻¹ ⋅ m ⋅ Base + s⁻¹ ⋅ R ⋅ publicKey)_x
    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        hash: &Self::HashVar,
        signature: &Self::SignatureVar,
        modulus: Self::ModulusVar,
    ) -> Result<Boolean<C::BaseField>, SynthesisError> {
        let s_inv = signature.s.inverse()?;
        let h = hash.0.clone();
        let base = parameters.generator.clone();
        let r = signature.r.clone();
        let public_key = public_key.public_key.clone();

        let lhs = s_inv.clone() * h;
        let lhs = lhs.to_bits_le()?;
        let lhs = base.scalar_mul_le(lhs.iter())?;

        let rhs = s_inv * r.clone();
        let rhs = rhs.to_bits_le()?;
        let rhs = public_key.scalar_mul_le(rhs.iter())?;

        let res = lhs + rhs;

        let res = res.to_bits_le()?;
        let res_x = res[0..res.len() / 2].to_vec();
        let res_x = Boolean::le_bits_to_fp_var(&res_x)?;

        let res_expected = r.to_bits_le()?;
        let res_expected = Boolean::le_bits_to_fp_var(&res_expected)?;

        is_same_num_in_mod(res_x.clone(), res_expected.clone(), modulus.clone())
    }
}

fn is_same_num_in_mod<Fq>(
    num1Var: FpVar<Fq>,
    num2Var: FpVar<Fq>,
    modulusVar: FpVar<Fq>,
) -> Result<Boolean<Fq>, SynthesisError>
where
    Fq: PrimeField,
{
    let cs = num1Var.cs();

    let numVar = num1Var - num2Var;
    let num_big_uint = numVar.value().unwrap_or_default().into_bigint().into();
    let fq_modulus_big_uint = Fq::MODULUS.into();
    let modulus = modulusVar.value().unwrap_or_default();
    let modulus_big_uint = modulus.into_bigint().into();

    let quotient = num_big_uint.clone() / modulus_big_uint.clone();
    let mut quotient = quotient.to_u64_digits();
    if quotient.is_empty() {
        quotient.push(0)
    }
    if quotient.len() != 1 {
        return Err(SynthesisError::AssignmentMissing);
    }
    let quotient_usize = quotient[0] as usize;
    let quotient = quotient[0];
    let quotient = Fq::from(quotient);
    let quotientVar = FpVar::<Fq>::new_witness(cs.clone(), || Ok(quotient))?;

    let max_quotient = fq_modulus_big_uint.clone() / modulus_big_uint.clone();
    let max_quotient = max_quotient.to_u64_digits();
    if max_quotient.len() != 1 {
        return Err(SynthesisError::AssignmentMissing);
    }
    let max_quotient = max_quotient[0];

    if quotient_usize > max_quotient as usize {
        return Err(SynthesisError::AssignmentMissing);
    }

    let mut quotient_index = vec![Fq::zero(); max_quotient as usize];
    quotient_index[quotient_usize] = Fq::one();
    let quotientIndexVar = quotient_index
        .iter()
        .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
        .collect::<Vec<FpVar<Fq>>>();
    quotientIndexVar.iter().for_each(|x| (x.clone() * (x - FpVar::one())).enforce_equal(&FpVar::zero()).unwrap());

    let zero_to_max: Vec<u64> = (0..=max_quotient).collect();
    let zero_to_max: Vec<Fq> = zero_to_max
        .iter()
        .map(|x| Fq::from(*x).mul(modulus))
        .collect();
    let zero_to_max = zero_to_max
        .iter()
        .map(|x| FpVar::<Fq>::new_constant(cs.clone(), *x).unwrap())
        .collect::<Vec<FpVar<Fq>>>();

    let res_expect = zero_to_max
        .iter()
        .zip(quotientIndexVar.iter())
        .map(|(x, y)| x * y)
        .collect::<Vec<FpVar<Fq>>>();
    let res_expect: FpVar<Fq> = res_expect.iter().sum();
    let res: FpVar<Fq> = quotientVar * modulusVar;

    res.is_eq(&res_expect)
}

#[cfg(test)]
mod test {
    use super::SignatureVerificationGadget;
    use crate::gadgets::ecdsa::constraints::ECDSAVerificationGadget;
    use crate::gadgets::ecdsa::{Hash, Signature, SignatureScheme, ECDSA};
    use ark_bn254;
    use ark_ec::{CurveGroup, Group};
    use ark_ed_on_bn254::constraints::FqVar;
    use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fq, Fr};
    use ark_ff::PrimeField;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::boolean::Boolean;
    use ark_r1cs_std::eq::EqGadget;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
    use ark_r1cs_std::groups::CurveVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::ns;
    use ark_relations::r1cs::Namespace;
    use ark_std::{test_rng, UniformRand};
    use std::ops::{Add, Mul};

    #[test]
    fn gadget_verify_test_one_time() {
        let mut rng = &mut test_rng();
        type MyECDSA = ECDSA<EdwardsProjective>;

        type MyECDSAGadget = ECDSAVerificationGadget<EdwardsProjective, EdwardsVar>;

        let parameter = MyECDSA::setup(rng).unwrap();
        let (sk, pk) = MyECDSA::keygen(&parameter, rng).unwrap();
        let hash = Hash(Fr::rand(rng));
        let signature = MyECDSA::sign(&parameter, &sk, &hash, rng).unwrap();
        let predict_res = MyECDSA::verify(&parameter, &pk, &hash, &signature).unwrap();

        let cs = ark_relations::r1cs::ConstraintSystem::<Fq>::new_ref();
        let parameterVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::ParametersVar::new_variable(
            ns!(cs, "parameter"),
            || Ok(&parameter),
            ark_r1cs_std::alloc::AllocationMode::Constant
        ).unwrap();

        let pkVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::PublicKeyVar::new_variable(
            ns!(cs, "pk"),
            || Ok(&pk),
            ark_r1cs_std::alloc::AllocationMode::Input
        ).unwrap();

        let hashVar =
            <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::HashVar::new_variable(
                ns!(cs, "hash"),
                || Ok(&hash),
                ark_r1cs_std::alloc::AllocationMode::Input,
            )
            .unwrap();

        let signatureVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::SignatureVar::new_variable(
            ns!(cs, "signature"),
            || Ok(&signature),
            ark_r1cs_std::alloc::AllocationMode::Witness
        ).unwrap();

        let modulus = Fr::MODULUS;
        let modulus = Fq::from_bigint(modulus).unwrap();
        let modulus = FpVar::<Fq>::new_constant(ns!(cs, "modulus"), modulus).unwrap();

        let res =
            MyECDSAGadget::verify(&parameterVar, &pkVar, &hashVar, &signatureVar, modulus).unwrap();
        println!(
            "check: {:?}",
            res.is_eq(&Boolean::TRUE).unwrap().value().unwrap()
        );
        assert_eq!(res.value().unwrap(), predict_res);
    }

    #[test]
    fn gadget_verify_test() {
        let mut rng = &mut test_rng();

        for i in 0..10 {
            type MyECDSA = ECDSA<EdwardsProjective>;

            type MyECDSAGadget = ECDSAVerificationGadget<EdwardsProjective, EdwardsVar>;

            let parameter = MyECDSA::setup(rng).unwrap();
            let (sk, pk) = MyECDSA::keygen(&parameter, rng).unwrap();
            let hash = Hash(Fr::rand(rng));
            let signature = MyECDSA::sign(&parameter, &sk, &hash, rng).unwrap();
            let predict_res = MyECDSA::verify(&parameter, &pk, &hash, &signature).unwrap();

            let cs = ark_relations::r1cs::ConstraintSystem::<Fq>::new_ref();
            let parameterVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::ParametersVar::new_variable(
                ns!(cs, "parameter"),
                || Ok(&parameter),
                ark_r1cs_std::alloc::AllocationMode::Constant
            ).unwrap();

            let pkVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::PublicKeyVar::new_variable(
                ns!(cs, "pk"),
                || Ok(&pk),
                ark_r1cs_std::alloc::AllocationMode::Input
            ).unwrap();

            let hashVar =
                <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::HashVar::new_variable(
                    ns!(cs, "hash"),
                    || Ok(&hash),
                    ark_r1cs_std::alloc::AllocationMode::Input,
                )
                .unwrap();

            let signatureVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::SignatureVar::new_variable(
                ns!(cs, "signature"),
                || Ok(&signature),
                ark_r1cs_std::alloc::AllocationMode::Witness
            ).unwrap();

            let modulus = Fr::MODULUS;
            let modulus = Fq::from_bigint(modulus).unwrap();
            let modulus = FpVar::<Fq>::new_constant(ns!(cs, "modulus"), modulus).unwrap();

            let res =
                MyECDSAGadget::verify(&parameterVar, &pkVar, &hashVar, &signatureVar, modulus)
                    .unwrap();
            println!(
                "check: {:?}",
                res.is_eq(&Boolean::TRUE).unwrap().value().unwrap()
            );
            assert_eq!(res.value().unwrap(), predict_res);
        }
    }

    #[test]
    fn gadget_verify_fail_test() {
        let mut rng = &mut test_rng();

        for i in 0..10 {
            type MyECDSA = ECDSA<EdwardsProjective>;

            type MyECDSAGadget = ECDSAVerificationGadget<EdwardsProjective, EdwardsVar>;

            let parameter = MyECDSA::setup(rng).unwrap();
            let (sk, pk) = MyECDSA::keygen(&parameter, rng).unwrap();
            let hash = Hash(Fr::rand(rng));

            // generate a fake signature
            let signature = Signature {
                r: Fr::rand(rng),
                s: Fr::rand(rng),
            };

            let predict_res = MyECDSA::verify(&parameter, &pk, &hash, &signature).unwrap();

            let cs = ark_relations::r1cs::ConstraintSystem::<Fq>::new_ref();
            let parameterVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::ParametersVar::new_variable(
                ns!(cs, "parameter"),
                || Ok(&parameter),
                ark_r1cs_std::alloc::AllocationMode::Input
            ).unwrap();

            let pkVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::PublicKeyVar::new_variable(
                ns!(cs, "pk"),
                || Ok(&pk),
                ark_r1cs_std::alloc::AllocationMode::Input
            ).unwrap();

            let hashVar =
                <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::HashVar::new_variable(
                    ns!(cs, "hash"),
                    || Ok(&hash),
                    ark_r1cs_std::alloc::AllocationMode::Input,
                )
                .unwrap();

            let signatureVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::SignatureVar::new_variable(
                ns!(cs, "signature"),
                || Ok(&signature),
                ark_r1cs_std::alloc::AllocationMode::Witness
            ).unwrap();

            let modulus = Fr::MODULUS;
            let modulus = Fq::from_bigint(modulus).unwrap();
            let modulus = FpVar::<Fq>::new_constant(ns!(cs, "modulus"), modulus).unwrap();

            let res =
                MyECDSAGadget::verify(&parameterVar, &pkVar, &hashVar, &signatureVar, modulus)
                    .unwrap_or(Boolean::FALSE);

            assert_eq!(predict_res, res.value().unwrap());
        }
    }
}
