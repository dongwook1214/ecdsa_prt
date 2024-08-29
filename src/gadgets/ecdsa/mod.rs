use ark_crypto_primitives::Error;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_std::rand::Rng;
use ark_std::{rand, UniformRand};
use std::marker::PhantomData;
use std::ops::Mul;

pub mod constraints;

pub trait SignatureScheme {
    type Parameters;
    type SecretKey;
    type PublicKey;
    type Signature;
    type Randomness;
    type Hash;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;
    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Error>;
    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        secret_key: &Self::SecretKey,
        hash: &Self::Hash,
        rng: &mut R,
    ) -> Result<Self::Signature, Error>;
    fn verify(
        parameters: &Self::Parameters,
        public_key: &Self::PublicKey,
        hash: &Self::Hash,
        signature: &Self::Signature,
    ) -> Result<bool, Error>;
}

pub struct ECDSA<C: CurveGroup> {
    _group: PhantomData<C>,
}

#[derive(Clone, Debug)]
pub struct Parameters<C: CurveGroup> {
    pub generator: C::Affine,
}

pub type PublicKey<C> = <C as CurveGroup>::Affine;

pub struct SecretKey<C: CurveGroup>(pub C::ScalarField);

#[derive(Clone, Debug)]
pub struct Signature<C: CurveGroup> {
    pub r: C::ScalarField,
    pub s: C::ScalarField,
}

#[derive(Clone, Debug)]
pub struct Randomness<C: CurveGroup>(pub C::ScalarField);
impl<C: CurveGroup> UniformRand for Randomness<C> {
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        Randomness(C::ScalarField::rand(rng))
    }
}

pub struct Hash<C: CurveGroup>(pub C::ScalarField);

impl<C: CurveGroup> SignatureScheme for ECDSA<C> {
    type Parameters = Parameters<C>;
    type SecretKey = SecretKey<C>;
    type PublicKey = PublicKey<C>;
    type Signature = Signature<C>;
    type Randomness = Randomness<C>;
    type Hash = Hash<C>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        let generator = C::rand(rng).into_affine();
        Ok(Parameters { generator })
    }

    fn keygen<R: Rng>(
        parameters: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Error> {
        let sk = C::ScalarField::rand(rng);
        let pk = parameters.generator.mul(sk);
        Ok((SecretKey(sk), pk.into_affine()))
    }

    /// k ← 𝔽r (random) P = k ⋅ g1Gen r = x_P (mod order) s = k⁻¹ . (m + sk ⋅ r) signature = {r, s}
    fn sign<R: Rng>(
        parameters: &Self::Parameters,
        secret_key: &Self::SecretKey,
        hash: &Self::Hash,
        rng: &mut R,
    ) -> Result<Self::Signature, Error> {
        let k: C::ScalarField = C::ScalarField::rand(rng);
        let p: C::Affine = parameters.generator.mul(k).into();
        let r = base_to_scalar(p.x().unwrap());
        let s = hash.0 + secret_key.0 * r;
        let s = k.inverse().unwrap() * s;

        Ok(Signature { r, s })
    }

    /// R ?= (s⁻¹ ⋅ m ⋅ Base + s⁻¹ ⋅ R ⋅ publicKey)_x
    fn verify(
        parameters: &Self::Parameters,
        public_key: &Self::PublicKey,
        hash: &Self::Hash,
        signature: &Self::Signature,
    ) -> Result<bool, Error> {
        let s_inv = signature.s.inverse().unwrap();
        // print all parameter
        println!(
            "s_inv: {:?} h: {:?} r: {:?} public_key: {:?} base: {:?}",
            s_inv, hash.0, signature.r, public_key, parameters.generator
        );

        println!("expected pk_x: {:?}", public_key.x().unwrap());
        println!("expected pk_y: {:?}", public_key.y().unwrap());

        let u1 = s_inv * hash.0;
        let u2 = s_inv * signature.r;

        let p: C::Affine = (parameters.generator.mul(u1) + public_key.mul(u2)).into();
        println!("expected lhs + rhs : {:?}", p);
        let r: C::ScalarField = base_to_scalar(p.x().unwrap());
        println!("expected_res : {:?}", r);
        Ok(r == signature.r)
    }
}

/// Convert a base field element into a scalar field element.
pub fn base_to_scalar<Fq: Field, Fr: PrimeField>(base_elem: &Fq) -> Fr {
    let mut base_elem_vec = Vec::new();
    base_elem
        .serialize_uncompressed(&mut base_elem_vec)
        .unwrap();
    Fr::from_le_bytes_mod_order(&base_elem_vec)
}

/// Convert a base field element into a scalar field element.
pub fn scalar_to_base<Fq: Field, Fr: PrimeField>(scalar_elem: &Fr) -> Fq {
    let mut scalar_elem_vec = Vec::new();
    scalar_elem
        .serialize_uncompressed(&mut scalar_elem_vec)
        .unwrap();
    Fq::from_random_bytes(&scalar_elem_vec).unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bn254;
    use ark_ff::{BigInt, One, PrimeField};
    use ark_r1cs_std::fields::fp::FpVar;
    use ark_ed_on_bn254;
    use ark_secp256k1;
    use ark_std::rand::SeedableRng;
    use ark_std::test_rng;

    #[test]
    fn test_base_to_scalar() {
        let fr_mod = (-ark_bn254::Fr::one()).into_bigint();
        let fr_mod = ark_bn254::Fq::from_bigint(fr_mod).unwrap();
        let fr_mod: BigInt<4> = base_to_scalar::<ark_bn254::Fq, ark_bn254::Fr>(&fr_mod).into();
        assert_eq!(fr_mod, (-ark_bn254::Fr::one()).into_bigint());
    }

    #[test]
    fn test_scalar_to_base() {
        let mut rng = &mut test_rng();
        let fr = ark_bn254::Fr::rand(rng);
        let fq_predict = ark_bn254::Fq::from_bigint(fr.into_bigint()).unwrap();
        let fq = scalar_to_base::<ark_bn254::Fq, ark_bn254::Fr>(&fr);
        assert_eq!(fq, fq_predict);
    }

    #[test]
    fn test_ecdsa_ed_bn254() {
        let mut rng = &mut test_rng();
        type MyCurveGroup = ark_ed_on_bn254::EdwardsProjective;
        let parameter = ECDSA::<MyCurveGroup>::setup(rng).unwrap();
        let (sk, pk) =
            ECDSA::<MyCurveGroup>::keygen(&parameter, rng).unwrap();
        let hash = Hash(ark_ed_on_bn254::Fr::rand(rng));
        let signature = ECDSA::<MyCurveGroup>::sign(
            &parameter,
            &sk,
            &hash,
            rng,
        )
        .unwrap();

        let output =
                ECDSA::<MyCurveGroup>::verify(&parameter, &pk, &hash, &signature).unwrap();
        assert_eq!(output, true);
    }

    #[test]
    fn test_ecdsa_bn254() {
        let mut rng = &mut test_rng();

        let parameter = ECDSA::<ark_bn254::G1Projective>::setup(rng).unwrap();
        let (sk, pk) =
            ECDSA::<ark_bn254::G1Projective>::keygen(&parameter, rng).unwrap();
        let hash = Hash(ark_bn254::Fr::rand(rng));
        let signature = ECDSA::<ark_bn254::G1Projective>::sign(
            &parameter,
            &sk,
            &hash,
            rng,
        )
            .unwrap();

        println!("signature: {:?}", signature);

            let output =
                ECDSA::<ark_bn254::G1Projective>::verify(&parameter, &pk, &hash, &signature).unwrap();
            assert_eq!(output, true);

    }

    #[test]
    fn test_ecdsa_secp256k1() {
        let mut rng = &mut test_rng();

        let parameter =
            ECDSA::<ark_secp256k1::Projective>::setup(rng).unwrap();
        let parameter = Parameters {
            generator: ark_secp256k1::Projective::generator().into_affine(),
        };
        let (sk, pk) =
            ECDSA::<ark_secp256k1::Projective>::keygen(&parameter,rng)
                .unwrap();
        let hash = Hash(ark_secp256k1::Fr::rand(rng));
        let signature = ECDSA::<ark_secp256k1::Projective>::sign(
            &parameter,
            &sk,
            &hash,
            rng,
        )
        .unwrap();
        let output =
            ECDSA::<ark_secp256k1::Projective>::verify(&parameter, &pk, &hash, &signature).unwrap();
        assert_eq!(output, true);
    }
}
