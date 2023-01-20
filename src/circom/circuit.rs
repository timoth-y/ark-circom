use std::collections::hash_map::Entry;
use std::collections::HashMap;
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
    pub witness: Option<Vec<(Option<String>, E::Fr)>>,
    pub(crate) _twisted_curve: PhantomData<C>,
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
                None => Some(w[1..self.r1cs.num_inputs].to_vec().into_iter().map(|(_, f)| f).collect()),
                Some(m) => Some(m[1..self.r1cs.num_inputs].iter().map(|i| w[*i].1).collect()),
            },
        }
    }

    pub fn allocate_variables(&self, cs: ConstraintSystemRef<C::BaseField>) -> Result<(
        HashMap<String, Vec<FpVar<C::BaseField>>>,
        HashMap<String, Vec<FpVar<C::BaseField>>>,
    ), SynthesisError> {
        let witness = &self.witness;
        let wire_mapping = &self.r1cs.wire_mapping;

        let mut external_inputs = HashMap::new();

        // Start from 1 because Arkworks implicitly allocates One for the first input
        for i in 1..self.r1cs.num_inputs {
            let (varname, fr) = match witness {
                None => (None, E::Fr::one()),
                Some(w) => match wire_mapping {
                    Some(m) => w[m[i + self.r1cs.num_inputs]].clone(),
                    None => w[i + self.r1cs.num_inputs].clone(),
                },
            };
            let fr: C::BaseField = fr.into();
            if let Some(varname) = varname {
                let var = FpVar::<C::BaseField>::new_input(ns!(cs, "circom_ark_binding"), || Ok(fr))?;
                match external_inputs.entry(varname) {
                    Entry::Vacant(e) => { e.insert(vec![var]); },
                    Entry::Occupied(mut e) => { e.get_mut().push(var); }
                };
            } else {
                cs.new_input_variable(|| {
                    Ok(fr)
                })?;
            }
        }

        let mut external_witnesses = HashMap::new();

        for i in 0..self.r1cs.num_aux {
            let (varname, fr) = match witness {
                None => (None, E::Fr::one()),
                Some(w) => match wire_mapping {
                    Some(m) => w[m[i + self.r1cs.num_inputs]].clone(),
                    None => w[i + self.r1cs.num_inputs].clone(),
                },
            };
            let fr: C::BaseField = fr.into();
            if let Some(varname) = varname {
                let var = FpVar::<C::BaseField>::new_witness(ns!(cs, "circom_ark_binding"), || Ok(fr))?;
                match external_witnesses.entry(varname) {
                    Entry::Vacant(e) => { e.insert(vec![var]); },
                    Entry::Occupied(mut e) => { e.get_mut().push(var); }
                }
            } else {
                cs.new_witness_variable(|| {
                    Ok(fr)
                })?;
            }
        }

        Ok((external_inputs, external_witnesses))
    }

    pub fn verify_linear_combinations(&self, cs: ConstraintSystemRef<C::BaseField>) -> Result<(), SynthesisError> {
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

impl<E: PairingEngine, C: ProjectiveCurve> ConstraintSynthesizer<C::BaseField> for CircomCircuit<E, C>
    where
        <C as ProjectiveCurve>::BaseField: From<<E as PairingEngine>::Fr>,
        C::BaseField: ark_ff::PrimeField {
    fn generate_constraints(self, cs: ConstraintSystemRef<C::BaseField>) -> Result<(), SynthesisError> {
        let _ = self.allocate_variables(cs.clone())?;

        self.verify_linear_combinations(cs.clone())
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
