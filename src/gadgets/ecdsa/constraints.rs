use crate::gadgets::ecdsa::{Hash, Parameters, PublicKey, Signature, SignatureScheme, ECDSA, base_to_scalar};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, Namespace, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::Zero;
use std::borrow::Borrow;
use std::marker::PhantomData;
use std::slice::Iter;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::{R1CSVar, ToBitsGadget};

pub trait SignatureVerificationGadget<
    C: SignatureScheme,
    ConstraintF: Field,
    ConstraintFr: PrimeField,
>
{
    type ParametersVar: AllocVar<C::Parameters, ConstraintF> + Clone;
    type PublicKeyVar: AllocVar<C::PublicKey, ConstraintF> + Clone;
    type SignatureVar: AllocVar<C::Signature, ConstraintFr> + Clone;
    type HashVar: AllocVar<C::Hash, ConstraintFr> + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        hash: &Self::HashVar,
        signature: &Self::SignatureVar,
    )-> Result<Boolean<ConstraintFr>, SynthesisError>;
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
pub struct SignatureVar<F: PrimeField> {
    pub r: FpVar<F>,
    pub s: FpVar<F>,
}

impl<C, F> AllocVar<Signature<C>, F> for SignatureVar<F>
where
    C: CurveGroup<ScalarField = F>,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let signature = f().map(|s| (s.borrow().r, s.borrow().s)).unwrap();
        let r = FpVar::new_variable(cs.clone(), || Ok(signature.0), mode)?;
        let s = FpVar::new_variable(cs, || Ok(signature.1), mode)?;
        Ok(Self { r, s })
    }
}

#[derive(Clone)]
pub struct HashVar<F: PrimeField>(pub FpVar<F>);

impl<C, F> AllocVar<Hash<C>, F> for HashVar<F>
where
    C: CurveGroup<ScalarField = F>,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Hash<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let hash = f().map(|h| h.borrow().0);
        let ns = cs.into();
        let cs = ns.cs();
        let hash = FpVar::new_variable(cs, || hash, mode)?;
        Ok(Self(hash))
    }
}

#[derive(Clone)]
pub struct ECDSAVerificationGadget<C: CurveGroup, GG: CurveVar<C, C::BaseField>> {
    #[doc(hidden)]
    _curve: PhantomData<C>,
    _field: PhantomData<GG>,
}

impl<C, GG> SignatureVerificationGadget<ECDSA<C>, C::BaseField, C::ScalarField>
    for ECDSAVerificationGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
{
    type ParametersVar = ParametersVar<C, GG>;
    type PublicKeyVar = PublicKeyVar<C, GG>;
    type SignatureVar = SignatureVar<C::ScalarField>;
    type HashVar = HashVar<C::ScalarField>;

    /// R ?= (s⁻¹ ⋅ m ⋅ Base + s⁻¹ ⋅ R ⋅ publicKey)_x
    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        hash: &Self::HashVar,
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<C::ScalarField>, SynthesisError>{
        unimplemented!()
        // let s_inv: FpVar<C::ScalarField> = signature.s.inverse()?;
        // let h: FpVar<C::ScalarField> = hash.0.clone();
        // let base = parameters.generator.clone();
        // let r: FpVar<C::ScalarField> = signature.r.clone();
        // let public_key = public_key.public_key.clone();
        //
        // let lhs: FpVar<C::ScalarField> = s_inv.clone() + h;
        // let lhs: Iter<Boolean<C::BaseField>> = lhs.to_bits_le()?.iter();
        // let lhs = base.scalar_mul_le(lhs)?;
        //
        // let rhs = s_inv + r.clone();
        // let rhs: Iter<Boolean<C::ScalarField>> = rhs.to_bits_le()?.iter();
        // let rhs = public_key.scalar_mul_le(rhs.into())?;
        //
        // let res = (lhs + rhs).value()?.into();
        // let res = res.x().unwrap().clone();
        // let res: C::ScalarField = base_to_scalar(res);
        // let res = res.eq(&r.value()?);
        //
        // Ok(Boolean::Constant(res))
    }
}


#[cfg(test)]
mod test{
    use ark_std::UniformRand;

    #[test]
    fn test(){
        let scalar = ark_bn254::Fr::from(0);

    }
}