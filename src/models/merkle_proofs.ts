import { SparseMerkleProof } from 'snarky-smt';
import { arrayProp, CircuitValue } from 'snarkyjs';

export class MerkleProofs extends CircuitValue {
  @arrayProp(SparseMerkleProof, 8) proofs: SparseMerkleProof[];

  constructor(proofs: SparseMerkleProof[]) {
    super();
    this.proofs = proofs;
  }
}
