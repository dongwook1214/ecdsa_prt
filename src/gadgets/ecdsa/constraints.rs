use crate::gadgets::ecdsa::{base_to_scalar, Hash, Parameters, PublicKey, Signature, SignatureScheme, ECDSA, scalar_to_base};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, Field, One, PrimeField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::uint8::UInt8;
use ark_r1cs_std::{R1CSVar, ToBitsGadget};
use ark_relations::r1cs::{ConstraintSynthesizer, Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::marker::PhantomData;
use std::ops::Mul;
use ark_bn254::Fq;
use ark_ed_on_bn254::constraints::FqVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::nonnative::{AllocatedNonNativeFieldVar, NonNativeFieldVar};



pub trait SignatureVerificationGadget<C: SignatureScheme, ConstraintF: PrimeField> {
    type ParametersVar: AllocVar<C::Parameters, ConstraintF> + Clone;
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
    pub s: NonNativeFieldVar<Fr,Fq>,
}

impl<C, Fr, Fq> AllocVar<Signature<C>, Fq> for SignatureVar<Fr, Fq>
where
    C: CurveGroup<ScalarField = Fr>,
    Fr: PrimeField,
    Fq: PrimeField,
{
    fn new_variable<T: Borrow<Signature<C>>>(cs: impl Into<Namespace<Fq>>, f: impl FnOnce() -> Result<T, SynthesisError>, mode: AllocationMode) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        f().map(|s|
            Self {
                r: NonNativeFieldVar::new_variable(cs.clone(), ||  Ok(s.borrow().r), mode).unwrap(),
                s: NonNativeFieldVar::new_variable(cs, || Ok(s.borrow().s), mode).unwrap()
            }
        )
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
    type PublicKeyVar = PublicKeyVar<C, GG>;
    type SignatureVar = SignatureVar<C::ScalarField, C::BaseField>;
    type HashVar = HashVar<C::ScalarField, C::BaseField>;

    /// R ?= (s⁻¹ ⋅ m ⋅ Base + s⁻¹ ⋅ R ⋅ publicKey)_x
    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        hash: &Self::HashVar,
        signature: &Self::SignatureVar,
        modulus: FpVar<C::BaseField>,
    ) -> Result<Boolean<C::BaseField>, SynthesisError> {
        let s_inv = signature.s.inverse()?;
        let h = hash.0.clone();
        let base = parameters.generator.clone();
        let r = signature.r.clone();
        let public_key = public_key.public_key.clone();

        println!("s_inv: {:?} h: {:?} r: {:?} public_key: {:?} base: {:?}", s_inv.value()?, h.value()?, r.value()?, public_key.value()?.into_affine(), base.value()?.into_affine());
        println!("pk: {:?}", public_key.value()?);

        let lhs = s_inv.clone() * h;
        let lhs = lhs.to_bits_le()?;
        let lhs = base.scalar_mul_le(lhs.iter())?;

        let rhs = s_inv * r.clone();
        let rhs = rhs.to_bits_le()?;
        let rhs = public_key.scalar_mul_le(rhs.iter())?;

        let res = lhs + rhs;
        println!("lhs + rhs: {:?}", res.value()?.into_affine());
        println!("lhs + rhs affine_x: {:?}", res.value()?.into_affine().x());
        println!("lhs + rhs projective: {:?}", res.value()?);

        let res = res.to_bits_le()?;
        let res_x = res[0..res.len()/2].to_vec();
        let res_x = Boolean::le_bits_to_fp_var(&res_x)?;

        println!("res_x: {:?}", res_x.value()?);

        let mut res_expected = r.to_bits_le()?;
        let res_expected = Boolean::le_bits_to_fp_var(&res_expected)?;
        println!("res_expected: {:?}", res_expected.value()?);

        is_same_num_in_mod(res_x.clone(), res_expected.clone(), modulus.clone())
    }
}

fn is_mod_zero<Fq> (num: FpVar<Fq>, modulus: FpVar<Fq>) -> Result< Boolean<Fq>, SynthesisError> where Fq:PrimeField {
    let num_value = num.value()?;
    let modulus_value = modulus.value()?;
    let quotient_value = num_value / modulus_value;
    if !num_value.is_zero() && ( quotient_value > num_value || modulus_value > num_value ) {
        println!("quotient_value: {:?} num_value: {:?} modulus_value: {:?}", quotient_value, num_value, modulus_value);
        return Ok(Boolean::FALSE)
    }
    println!("quotient_value: {:?} ", quotient_value);
    let quotientVar = FpVar::<Fq>::new_constant(num.cs(), quotient_value)?;
    quotientVar.enforce_cmp(&num, Ordering::Less, true)?;
    modulus.enforce_cmp(&num, Ordering::Less, true)?;
    let resVar = modulus.mul(&quotientVar);
    resVar.enforce_equal(&num)?;

    // let twoVar = FpVar::<Fq>::new_constant(num.cs(), Fq::from(2u32))?;
    // let quotientVar = quotientVar.mul_by_inverse(&twoVar)?;
    // let resVar = modulus.mul(&quotientVar);
    // resVar.enforce_cmp(&num, Ordering::Less, false)?;
    return Ok(Boolean::TRUE)
}

fn is_same_num_in_mod<Fq>(num1Var: FpVar<Fq>, num2Var: FpVar<Fq>, modulusVar: FpVar<Fq>) -> Result<Boolean<Fq>, SynthesisError> where Fq:PrimeField {
    let numVar = num1Var - num2Var;
    let num = numVar.value()?;
    let modulus = modulusVar.value()?;
    let quotient = num / modulus;
    let max_quotient = Fq::MODULUS.into() / modulus.into_bigint().into();
    let max_quotient = Fq::from_bigint(Fq::BigInt::try_from(max_quotient).unwrap()).unwrap();

    println!("max_quotient: {:?} quotient: {:?}", max_quotient, quotient);

    if quotient > max_quotient {
        return Ok(Boolean::FALSE)
    }

    let quotientVar = FpVar::<Fq>::new_witness(numVar.cs(), ||Ok(quotient))?;
    let maxQuotientVar = FpVar::<Fq>::new_witness(quotientVar.cs(), ||Ok(max_quotient))?;
    let actual_num = modulusVar.clone().mul(&quotientVar);
    actual_num.enforce_equal(&numVar)?;
    quotientVar.enforce_cmp(&maxQuotientVar, Ordering::Less, true)?;

    let mustBiggerVar = modulusVar.clone().mul(&maxQuotientVar);
    let mustSmallerVar = modulusVar.clone().mul(&(maxQuotientVar + FpVar::<Fq>::new_constant(quotientVar.cs(), Fq::one())?));

    modulusVar.enforce_cmp(&mustBiggerVar, Ordering::Less, true)?;
    modulusVar.enforce_cmp(&mustSmallerVar, Ordering::Greater, false)?;

    println!("max_quotient: {:?} quotient: {:?}", max_quotient, quotient);

    Ok(Boolean::TRUE)
}

#[cfg(test)]
mod test {
    use std::ops::{Add, Mul};
    use ark_bn254;
    use ark_ec::{CurveGroup, Group};
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::groups::CurveVar;
    use crate::gadgets::ecdsa::{Hash, SignatureScheme, ECDSA, Signature};
    use ark_std::{test_rng, UniformRand};
    use crate::gadgets::ecdsa::constraints::ECDSAVerificationGadget;
    use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fq, Fr};
    use ark_ed_on_bn254::constraints::FqVar;
    use ark_ff::PrimeField;
    use ark_r1cs_std::boolean::Boolean;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::ns;
    use ark_relations::r1cs::Namespace;
    use super::SignatureVerificationGadget;
    #[test]
    fn gadget_verify_test() {
        let mut rng = &mut test_rng();

        for i in 0..10 {
            type MyECDSA = ECDSA<EdwardsProjective>;

            type MyECDSAGadget = ECDSAVerificationGadget<EdwardsProjective, EdwardsVar>;

            let parameter = MyECDSA::setup(rng).unwrap();
            let (sk, pk) =
                MyECDSA::keygen(&parameter, rng).unwrap();
            let hash = Hash(Fr::rand(rng));
            let signature = MyECDSA::sign(
                &parameter,
                &sk,
                &hash,
                rng,
            )
                .unwrap();
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

            let hashVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::HashVar::new_variable(
                ns!(cs, "hash"),
                || Ok(&hash),
                ark_r1cs_std::alloc::AllocationMode::Input
            ).unwrap();

            let signatureVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::SignatureVar::new_variable(
                ns!(cs, "signature"),
                || Ok(&signature),
                ark_r1cs_std::alloc::AllocationMode::Witness
            ).unwrap();

            let modulus = Fr::MODULUS;
            let modulus = Fq::from_bigint(modulus).unwrap();
            let modulus = FpVar::<Fq>::new_constant(ns!(cs, "modulus"), modulus).unwrap();

            let res = MyECDSAGadget::verify(&parameterVar, &pkVar, &hashVar, &signatureVar, modulus).unwrap();

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
            let (sk, pk) =
                MyECDSA::keygen(&parameter, rng).unwrap();
            let hash = Hash(Fr::rand(rng));

            // generate a fake signature
            let signature = Signature {
                r: Fr::rand(rng),
                s: Fr::rand(rng)
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

            let hashVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::HashVar::new_variable(
                ns!(cs, "hash"),
                || Ok(&hash),
                ark_r1cs_std::alloc::AllocationMode::Input
            ).unwrap();

            let signatureVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, Fq>>::SignatureVar::new_variable(
                ns!(cs, "signature"),
                || Ok(&signature),
                ark_r1cs_std::alloc::AllocationMode::Witness
            ).unwrap();

            let modulus = Fr::MODULUS;
            let modulus = Fq::from_bigint(modulus).unwrap();
            let modulus = FpVar::<Fq>::new_constant(ns!(cs, "modulus"), modulus).unwrap();

            let res = MyECDSAGadget::verify(&parameterVar, &pkVar, &hashVar, &signatureVar, modulus).unwrap_or(Boolean::FALSE);

            assert_eq!(predict_res, res.value().unwrap());
        }
    }

}

