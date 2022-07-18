use ark_ec::{PairingEngine, ProjectiveCurve};
use std::{fs::File, path::Path};

use super::{CircomCircuit, R1CS};

use num_bigint::{BigInt, Sign};
use std::collections::HashMap;
use std::marker::PhantomData;
use ark_ff::to_bytes;

use crate::{circom::R1CSFile, witness::WitnessCalculator};
use color_eyre::Result;

#[derive(Clone, Debug)]
pub struct CircomBuilder<E: PairingEngine, C: ProjectiveCurve> {
    pub cfg: CircomConfig<E>,
    pub inputs: HashMap<String, Vec<(BigInt, Option<E::Fr>)>>,
    _twisted_curve: PhantomData<C>
}

// Add utils for creating this from files / directly from bytes
#[derive(Clone, Debug)]
pub struct CircomConfig<E: PairingEngine> {
    pub r1cs: R1CS<E>,
    pub wtns: WitnessCalculator,
    pub sanity_check: bool,
}

impl<E: PairingEngine> CircomConfig<E> {
    pub fn new(wtns: impl AsRef<Path>, r1cs: impl AsRef<Path>) -> Result<Self> {
        let wtns = WitnessCalculator::new(wtns).unwrap();
        let reader = File::open(r1cs)?;
        let r1cs = R1CSFile::new(reader)?.into();
        Ok(Self {
            wtns,
            r1cs,
            sanity_check: false,
        })
    }
}

impl<E: PairingEngine, C: ProjectiveCurve> CircomBuilder<E, C>
    where C::BaseField: From<E::Fr>, E::Fr: From<C::BaseField>, C::BaseField: ark_ff::PrimeField{
    /// Instantiates a new builder using the provided WitnessGenerator and R1CS files
    /// for your circuit
    pub fn new(cfg: CircomConfig<E>) -> Self {
        Self {
            cfg,
            inputs: HashMap::new(),
            _twisted_curve: PhantomData
        }
    }

    /// Pushes a Circom input at the specified name.
    pub fn push_input<T: Into<BigInt>>(&mut self, name: impl ToString, val: T) {
        let values = self.inputs.entry(name.to_string()).or_insert_with(Vec::new);
        values.push((val.into(), None));
    }

    /// Pushes a Circom input at the specified name.
    pub fn push_variable(&mut self, name: impl ToString, var: C::BaseField) {
        let values = self.inputs.entry(name.to_string()).or_insert_with(Vec::new);
        let val = BigInt::from_bytes_le(Sign::Plus, &to_bytes!(var).unwrap());
        values.push((val, Some(var.into())));
    }

    /// Generates an empty circom circuit with no witness set, to be used for
    /// generation of the trusted setup parameters
    pub fn setup(&self) -> CircomCircuit<E, C> {
        let mut circom = CircomCircuit {
            r1cs: self.cfg.r1cs.clone(),
            witness: None,
            _twisted_curve: PhantomData
        };

        // Disable the wire mapping
        circom.r1cs.wire_mapping = None;

        circom
    }

    /// Creates the circuit populated with the witness corresponding to the previously
    /// provided inputs
    pub fn build(mut self) -> Result<CircomCircuit<E, C>> {
        let mut circom = self.setup();

        // calculate the witness
        let witness = self
            .cfg
            .wtns
            .calculate_witness_element::<E, _>(self.inputs, self.cfg.sanity_check)?;
        println!("witness size: {}, external of them {}",witness.len(), witness.iter().filter(|(_,e)| *e).collect::<Vec<_>>().len());
        circom.witness = Some(witness);

        // sanity check
        debug_assert!({
            use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
            let cs = ConstraintSystem::<C::BaseField>::new_ref();
            circom.clone().generate_constraints(cs.clone()).unwrap();
            let is_satisfied = cs.is_satisfied().unwrap();
            if !is_satisfied {
                println!(
                    "Unsatisfied constraint: {:?}",
                    cs.which_is_unsatisfied().unwrap()
                );
            }

            is_satisfied
        });

        Ok(circom)
    }
}
