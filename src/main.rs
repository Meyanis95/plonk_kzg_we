use std::marker::PhantomData;

use halo2_backend::poly::{Coeff, Polynomial};
use halo2_middleware::zal::impls::PlonkEngineConfig;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine, G1};
use halo2_proofs::poly::commitment::{Blind, Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2_proofs::poly::EvaluationDomain;
use rand::rngs::OsRng;

use plonk_kzg_we::{eval_polynomial, poly_divide};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Choice {
    Zero,
    One,
}

impl Choice {
    pub fn to_fr<F: Field>(&self) -> Fr {
        match self {
            Choice::Zero => Fr::from(0),
            Choice::One => Fr::from(1),
        }
    }
}

#[derive(Debug)]
pub struct LaconicOTRecv {
    params: ParamsKZG<Bn256>,
    qs: Vec<G1>,
    com: G1,
    bits: Vec<Choice>,
}

impl LaconicOTRecv {
    pub fn new(params: ParamsKZG<Bn256>, bits: &[Choice], k: u32) -> Self {
        let params: ParamsKZG<Bn256> = ParamsKZG::setup(k, &mut OsRng);

        let mut elems: Vec<_> = bits
            .iter()
            .map(|b| {
                if *b == Choice::One {
                    Fr::from(1)
                } else {
                    Fr::from(0)
                }
            })
            .collect();

        // pad with random elements, comment out for now
        // assert!(elems.len() <= ck.domain.size());
        // elems.resize_with(ck.domain.size(), || {
        //     E::ScalarField::rand(&mut ark_std::test_rng())
        // });

        // Compute the commitment using `ParamsKZG`'s `commit_lagrange` function,
        // with default blinding factor and Plonk engine
        let engine = PlonkEngineConfig::build_default::<G1Affine>();
        let alpha = Blind::default();

        // Create evaluation domain
        let domain = EvaluationDomain::new(1, k);

        let mut a = domain.empty_lagrange();
        for (i, a) in a.iter_mut().enumerate() {
            if i < elems.len() {
                *a = elems[i];
            } else {
                *a = Fr::zero();
            }
        }

        // compute commitment
        let commitment = params.commit_lagrange(&engine.msm_backend, &a, alpha);

        // Convert polynomial f from Lagrange to coefficient form.
        let poly_coeff = domain.lagrange_to_coeff(a.clone());

        // Get domain points
        let n = elems.len();
        let points: Vec<Fr> = (0..n)
            .map(|i| domain.get_omega().pow(&[i as u64]))
            .collect();

        // Openings at the points
        let qs: Vec<G1> = points
            .iter()
            .map(|&z| {
                // Evaluate f at z.
                let f_z = eval_polynomial(&poly_coeff.values, z);

                // Compute quotient q(x) = (f(x) - f(z)) / (x - z).
                let quotient: Vec<Fr> = poly_divide(&poly_coeff.values, z, f_z);
                let quotient_poly = Polynomial {
                    values: quotient,
                    _marker: PhantomData::<Coeff>,
                };

                // Commit to the quotient polynomial (in coefficient form).
                let point = params.commit(&engine.msm_backend, &quotient_poly, alpha);
                point
            })
            .collect();

        Self {
            params,
            qs,
            com: commitment.into(),
            bits: bits.to_vec(),
        }
    }

    // pub fn recv(&self, i: usize, msg: Msg<E>) -> [u8; MSG_SIZE] {
    //     let j: usize = if self.bits[i] == Choice::One { 1 } else { 0 };
    //     let h = msg.h[j].0;
    //     let c = msg.h[j].1;
    //     let m = E::pairing(self.qs[i], h);
    //     decrypt::<E, MSG_SIZE>(m.0, &c)
    // }

    // pub fn commitment(&self) -> E::G1 {
    //     self.com
    // }
}

fn main() {
    let bits = vec![Choice::One, Choice::Zero, Choice::One, Choice::Zero];
    let k = 4;
    let params: ParamsKZG<Bn256> = ParamsKZG::setup(k, &mut OsRng);
    let ot_recv = LaconicOTRecv::new(params, &bits, k);
    println!("{:?}", ot_recv);
}
