import { SparseMerkleProof } from 'snarky-smt';
import { arrayProp, CircuitValue, isReady, prop } from 'snarkyjs';
import { Note as Note } from './note';

await isReady;

export const MAX_INPUT_NOTES = 6;

export class InputNotes extends CircuitValue {
  @arrayProp(Note, MAX_INPUT_NOTES) notes: Note[];
  @arrayProp(SparseMerkleProof, MAX_INPUT_NOTES)
  membershipProofs: SparseMerkleProof[];
  @arrayProp(SparseMerkleProof, MAX_INPUT_NOTES)
  nullifierProofs: SparseMerkleProof[];

  constructor(
    notes: Note[],
    membershipProofs: SparseMerkleProof[],
    nullifierProofs: SparseMerkleProof[]
  ) {
    super();
    this.notes = notes;
    this.membershipProofs = membershipProofs;
    this.nullifierProofs = nullifierProofs;
  }
}

export const MAX_OUTPUT_NOTEINFOS = 2;

export class OutputNotes extends CircuitValue {
  @prop senderNote: Note;
  @prop receiverNote: Note;

  constructor(senderNote: Note, receiverNote: Note) {
    super();
    this.senderNote = senderNote;
    this.receiverNote = receiverNote;
  }
}
