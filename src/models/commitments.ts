import { SparseMerkleTree } from 'snarky-smt';
import { arrayProp, Bool, CircuitValue, Field } from 'snarkyjs';

const MAX_COMMITMENTS = 2;

export class Commitments extends CircuitValue {
  @arrayProp(Field, MAX_COMMITMENTS) commitments: Field[];

  constructor(commitments: Field[]) {
    super();
    this.commitments = commitments;
  }

  static createInitCommitments(): Commitments {
    let commitments = new Array(MAX_COMMITMENTS).fill(
      SparseMerkleTree.initialPoseidonHashRoot
    );
    return new Commitments(commitments);
  }

  updateLatestCommitment(root: Field) {
    for (let i = 0; i < MAX_COMMITMENTS - 1; i++) {
      this.commitments[i] = this.commitments[i + 1];
    }

    this.commitments[MAX_COMMITMENTS - 1] = root;
  }

  containsCommitment(root: Field): Bool {
    return this.commitments.map((v) => root.equals(v)).reduce(Bool.or);
  }

  toString(): string {
    return this.toFields().toString();
  }
}
