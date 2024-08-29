use crate::gadgets::ecdsa::{base_to_scalar, Hash, Parameters, PublicKey, Signature, SignatureScheme, ECDSA, scalar_to_base};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, One, PrimeField};
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
use std::marker::PhantomData;
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
    ) -> Result<Boolean<C::BaseField>, SynthesisError> {
        let s_inv = signature.s.inverse()?;
        let h = hash.0.clone();
        let base = parameters.generator.clone();
        let r = signature.r.clone();
        let public_key = public_key.public_key.clone();

        println!("pk: {}", public_key.value()?);
        let pk = public_key.to_bits_le()?;
        let pk_x = pk[0..pk.len()/2].to_vec();
        let pk_y = pk[pk.len()/2..pk.len()].to_vec();
        let pk_x = Boolean::le_bits_to_fp_var(&pk_x)?;
        let pk_y = Boolean::le_bits_to_fp_var(&pk_y)?;
        println!("pk_x: {:?}", pk_x.value()?);
        println!("pk_y: {:?}", pk_y.value()?);

        println!("s_inv: {:?} h: {:?} r: {:?} public_key: {:?} base: {:?}", s_inv.value()?, h.value()?, r.value()?, public_key.value()?.into_affine(), base.value()?.into_affine());

        let lhs = s_inv.clone() * h;
        let lhs = lhs.to_bits_le()?;
        let lhs = base.scalar_mul_le(lhs.iter())?;

        let rhs = s_inv * r.clone();
        let rhs = rhs.to_bits_le()?;
        let rhs = public_key.scalar_mul_le(rhs.iter())?;

        let res = lhs + rhs;
        println!("lhs + rhs: {:?}", res.value()?.into_affine());
        let res = res.to_bits_le()?;
        let res = res[0..res.len()/2].to_vec();
        let res_y = res[res.len()/2..res.len()].to_vec();
        let res = Boolean::le_bits_to_fp_var(&res)?;
        let res_y = Boolean::le_bits_to_fp_var(&res_y)?;


        let res_expected = r.to_bits_le()?;
        let res_expected = Boolean::le_bits_to_fp_var(&res_expected)?;

        println!("res: {:?}", res.value()?);
        println!("res_y: {:?}", res_y.value()?);

        res_expected.is_eq(&res)
    }
}

#[cfg(test)]
mod test {
    use std::ops::{Add, Mul};
    use ark_bn254;
    use ark_ec::{CurveGroup, Group};
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::groups::CurveVar;
    use crate::gadgets::ecdsa::{Hash, SignatureScheme, ECDSA};
    use ark_std::{test_rng, UniformRand};
    use crate::gadgets::ecdsa::constraints::ECDSAVerificationGadget;
    use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fq, Fr};
    use ark_ed_on_bn254::constraints::FqVar;
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::ns;
    use ark_relations::r1cs::Namespace;
    use super::SignatureVerificationGadget;
    #[test]
    fn gadget_verify_test() {
        let mut rng = &mut test_rng();

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

        let res = MyECDSAGadget::verify(&parameterVar, &pkVar, &hashVar, &signatureVar).unwrap();

        assert!(res.value().unwrap());
    }

}

