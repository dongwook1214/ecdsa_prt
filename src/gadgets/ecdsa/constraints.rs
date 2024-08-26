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
use std::slice::Iter;

pub trait SignatureVerificationGadget<C: SignatureScheme, ConstraintF: Field> {
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
pub struct SignatureVar<F: PrimeField> {
    pub r: FpVar<F>,
    pub s: FpVar<F>,
}

impl<C, F> AllocVar<Signature<C>, F> for SignatureVar<F>
where
    C: CurveGroup<BaseField = F>,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let ns = cs.into();
        let cs = ns.cs();
        let signature:(F, F) = f().map(|s| (scalar_to_base(&s.borrow().r), scalar_to_base(&s.borrow().s))).unwrap();
        let r = FpVar::new_variable(cs.clone(), || Ok(signature.0), mode)?;
        let s = FpVar::new_variable(cs, || Ok(signature.1), mode)?;
        Ok(Self { r, s })
    }
}

#[derive(Clone)]
pub struct HashVar<F: PrimeField>(pub FpVar<F>);

impl<C, F> AllocVar<Hash<C>, F> for HashVar<F>
where
    C: CurveGroup<BaseField = F>,
    F: PrimeField,
{
    fn new_variable<T: Borrow<Hash<C>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let hash: Result<F ,SynthesisError> = f().map(|h| scalar_to_base(&h.borrow().0));
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

impl<C, GG> SignatureVerificationGadget<ECDSA<C>, C::BaseField> for ECDSAVerificationGadget<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    C::BaseField: PrimeField,
{
    type ParametersVar = ParametersVar<C, GG>;
    type PublicKeyVar = PublicKeyVar<C, GG>;
    type SignatureVar = SignatureVar<C::BaseField>;
    type HashVar = HashVar<C::BaseField>;

    /// R ?= (s⁻¹ ⋅ m ⋅ Base + s⁻¹ ⋅ R ⋅ publicKey)_x
    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        hash: &Self::HashVar,
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<C::BaseField>, SynthesisError> {
        let s_inv: FpVar<C::BaseField> = signature.s.inverse()?;
        let h: FpVar<C::BaseField> = hash.0.clone();
        let base = parameters.generator.clone();
        let r: FpVar<C::BaseField> = signature.r.clone();
        let public_key = public_key.public_key.clone();

        println!("s_inv: {:?} h: {:?} r: {:?} public_key: {:?}", s_inv.value()?, h.value()?, r.value()?, public_key.value()?);

        let lhs: FpVar<C::BaseField> = s_inv.clone() * h;
        let lhs: Vec<Boolean<C::BaseField>> = lhs.to_bits_le()?;
        let lhs = base.scalar_mul_le(lhs.iter())?;

        let rhs = s_inv * r.clone();
        let rhs = rhs.to_bits_le()?;
        let rhs = public_key.scalar_mul_le(rhs.iter())?;

        let res = (lhs + rhs).value()?.into();
        let res = res.x().unwrap().clone();
        println!("res: {:?} real_res: {:?}", res, &r.value()?);

        let res = res.eq(&r.value()?);

        Ok(Boolean::Constant(res))
    }
}


// compute s⁻¹ with C::ScalarField::MODULUS: use extended euclidean algorithm
// fn get_inverse_in_ScalarField  <C: CurveGroup> (s: FpVar<C::BaseField>)-> FpVar<C::BaseField> where C::BaseField: PrimeField {
//     let modulus = C::ScalarField::MODULUS;
//     let mut t = FpVar::<C::BaseField>::Constant(<C::BaseField>::zero());
//     let mut new_t = FpVar::<C::BaseField>::Constant(<C::BaseField>::one());
//     let mut r = s.clone();
//     let mut new_r =FpVar::<C::BaseField>::Constant(scalar_to_base(C::ScalarField::from_bigint(modulus).unwrap()));
//     while !r.is_constant() {
//         let quotient = r.mul_by_inverse(&new_r)?;
//         let tmp = new_r.clone();
//         new_r = r.clone() - quotient.clone() * new_r.clone();
//         r = tmp;
//         let tmp = new_t.clone();
//         new_t = t.clone() - quotient.clone() * new_t.clone();
//         t = tmp;
//     }
//     t
// }

#[cfg(test)]
mod test {
    use std::ops::{Add, Mul};
    use ark_bn254;
    use ark_ec::CurveGroup;
    use ark_r1cs_std::alloc::AllocVar;
    use ark_r1cs_std::groups::CurveVar;
    use crate::gadgets::ecdsa::{Hash, SignatureScheme, ECDSA};
    use ark_std::UniformRand;
    use crate::gadgets::ecdsa::constraints::ECDSAVerificationGadget;
    use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fq, Fr};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_r1cs_std::R1CSVar;
    use super::SignatureVerificationGadget;

    #[test]
    fn gadget_verify_test() {
        type MyECDSA = ECDSA<EdwardsProjective>;

        type MyECDSAGadget = ECDSAVerificationGadget<EdwardsProjective, EdwardsVar>;

        let parameter = MyECDSA::setup(&mut ark_std::test_rng()).unwrap();
        let (sk, pk) =
            MyECDSA::keygen(&parameter, &mut ark_std::test_rng()).unwrap();
        let hash = Hash(Fr::rand(&mut ark_std::test_rng()));
        let signature = MyECDSA::sign(
            &parameter,
            &sk,
            &hash,
            &mut ark_std::test_rng(),
        )
        .unwrap();

        let predict_res = MyECDSA::verify(&parameter, &pk, &hash, &signature).unwrap();
        println!("predict_res: {:?}", predict_res);


        let cs = ark_relations::r1cs::ConstraintSystem::<Fq>::new_ref();

        let parameterVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, <EdwardsProjective as CurveGroup>::BaseField >>::ParametersVar::new_input(
            ark_relations::ns!(cs, "parameter"),
            || Ok(&parameter),
        ).unwrap();

        let pkVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, <EdwardsProjective as CurveGroup>::BaseField >>::PublicKeyVar::new_input(
            ark_relations::ns!(cs, "pk"),
            || Ok(&pk),
        ).unwrap();

        let hashVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, <EdwardsProjective as CurveGroup>::BaseField >>::HashVar::new_input(
            ark_relations::ns!(cs, "hash"),
            || Ok(&hash),
        ).unwrap();

        let signatureVar = <MyECDSAGadget as SignatureVerificationGadget<MyECDSA, <EdwardsProjective as CurveGroup>::BaseField >>::SignatureVar::new_witness(
            ark_relations::ns!(cs, "signature"),
            || Ok(&signature),
        ).unwrap();

        let res = MyECDSAGadget::verify(&parameterVar, &pkVar, &hashVar, &signatureVar).unwrap();
        println!("res: {:?}", res.value().unwrap());
    }

    #[test]
    fn fp_var_test(){
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        let fp_var = FpVar::new_variable(cs.clone(), ||Ok(Fr::rand(&mut ark_std::test_rng())), ark_r1cs_std::alloc::AllocationMode::Witness).unwrap();
        let fp_var2 = FpVar::new_variable(cs.clone(), ||Ok(Fr::rand(&mut ark_std::test_rng())), ark_r1cs_std::alloc::AllocationMode::Witness).unwrap();
        let fp_var3 = fp_var.clone().add(&fp_var2);
        let fp_var4 = fp_var.mul(&fp_var2);

        println!("{:?}",fp_var3)
    }
}
