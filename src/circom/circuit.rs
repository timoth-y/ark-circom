use std::marker::PhantomData;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::ns;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ark_r1cs_std::fields::fp::FpVar;

use super::R1CS;

use color_eyre::Result;
use ethers_core::k256::elliptic_curve::PrimeField;
use num_traits::One;

#[derive(Clone, Debug)]
pub struct CircomCircuit<E: PairingEngine, C: ProjectiveCurve> {
    pub r1cs: R1CS<E>,
    pub witness: Option<Vec<(E::Fr, bool)>>,
    pub(crate) _twisted_curve: PhantomData<C>
}

impl<'a, E: PairingEngine, C: ProjectiveCurve> CircomCircuit<E, C>
    where
        <C as ProjectiveCurve>::BaseField: From<<E as PairingEngine>::Fr>,
        C::BaseField: ark_ff::PrimeField
{
    pub fn get_public_inputs(&self) -> Option<Vec<E::Fr>> {
        match &self.witness {
            None => None,
            Some(w) => match &self.r1cs.wire_mapping {
                None => Some(w[1..self.r1cs.num_inputs].to_vec().into_iter().map(|(f, _)| f).collect()),
                Some(m) => Some(m[1..self.r1cs.num_inputs].iter().map(|i| w[*i].0).collect()),
            },
        }
    }

    pub fn allocate_variables(&self, cs: ConstraintSystemRef<C::BaseField>) -> Result<(Vec<FpVar<C::BaseField>>, Vec<FpVar<C::BaseField>>), SynthesisError> {
        let witness = &self.witness;
        let wire_mapping = &self.r1cs.wire_mapping;

        let mut external_inputs = vec![];

        // Start from 1 because Arkworks implicitly allocates One for the first input
        for i in 1..self.r1cs.num_inputs {
            let (f, is_external) = match witness {
                None => (E::Fr::one(), false),
                Some(w) => match wire_mapping {
                    Some(m) => w[m[i]],
                    None => w[i],
                },
            };
            let f: C::BaseField = f.into();
            if is_external {
                external_inputs.push(
                    FpVar::<C::BaseField>::new_input(ns!(cs, "plaintext"), || {
                        Ok(f)
                    })?
                )
            } else {
                cs.new_input_variable(|| {
                    Ok(f)
                })?;
            }

        }

        let mut external_witnesses = vec![];

        for i in 0..self.r1cs.num_aux {
            let (f, is_external) = match witness {
                None => (E::Fr::one(), false),
                Some(w) => match wire_mapping {
                    Some(m) => w[m[i + self.r1cs.num_inputs]],
                    None => w[i + self.r1cs.num_inputs],
                },
            };
            let f: C::BaseField = f.into();

            if is_external {
                external_witnesses.push(
                    FpVar::<C::BaseField>::new_witness(ns!(cs, "plaintext"), || {
                        Ok(f)
                    })?
                )
            } else {
                cs.new_witness_variable(|| {
                    Ok(f)
                })?;
            }
        }

        Ok((external_inputs, external_witnesses))
    }
}

impl<E: PairingEngine, C: ProjectiveCurve> ConstraintSynthesizer<C::BaseField> for CircomCircuit<E, C>
    where <C as ProjectiveCurve>::BaseField: From<<E as PairingEngine>::Fr> {
    fn generate_constraints(self, cs: ConstraintSystemRef<C::BaseField>) -> Result<(), SynthesisError> {
        let make_index = |index| {
            if index < self.r1cs.num_inputs {
                Variable::Instance(index)
            } else {
                Variable::Witness(index - self.r1cs.num_inputs)
            }
        };
        let make_lc = |lc_data: &[(usize, E::Fr)]| {
            lc_data.iter().fold(
                LinearCombination::<C::BaseField>::zero(),
                |lc: LinearCombination<C::BaseField>, (index, coeff)| {
                    let f: C::BaseField = (*coeff).into();
                    lc + (f, make_index(*index))
                },
            )
        };

        for constraint in &self.r1cs.constraints {
            cs.enforce_constraint(
                make_lc(&constraint.0),
                make_lc(&constraint.1),
                make_lc(&constraint.2),
            )?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CircomBuilder, CircomConfig};
    use ark_bn254::{Bn254, Fr};
    use ark_ed_on_bn254::{EdwardsProjective, Fq};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn satisfied() {
        let cfg = CircomConfig::<Bn254>::new(
            "./test-vectors/mycircuit.wasm",
            "./test-vectors/mycircuit.r1cs",
        )
        .unwrap();
        let mut builder = CircomBuilder::<_, EdwardsProjective>::new(cfg);
        builder.push_input("a", 3);
        builder.push_input("b", 11);

        let circom = builder.build().unwrap();
        let cs = ConstraintSystem::<Fq>::new_ref();
        circom.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
