import { SparseMerkleProof } from 'snarky-smt';
import { arrayProp, CircuitValue, isReady, prop } from 'snarkyjs';
import { Note } from './note';
import { NoteInfo } from './note_info';

await isReady;

export const MAX_INPUT_NOTES = 2;

export class InputNoteInfos extends CircuitValue {
  @arrayProp(NoteInfo, MAX_INPUT_NOTES) noteInfos: NoteInfo[];
  @arrayProp(SparseMerkleProof, MAX_INPUT_NOTES)
  membershipProofs: SparseMerkleProof[];
  @arrayProp(SparseMerkleProof, MAX_INPUT_NOTES)
  nullifierProofs: SparseMerkleProof[];

  constructor(
    noteInfos: NoteInfo[],
    membershipProofs: SparseMerkleProof[],
    nullifierProofs: SparseMerkleProof[]
  ) {
    super();
    this.noteInfos = noteInfos;
    this.membershipProofs = membershipProofs;
    this.nullifierProofs = nullifierProofs;
  }
}

export const MAX_OUTPUT_NOTEINFOS = 2;

export class OutputNotes extends CircuitValue {
  @prop senderNote: Note;
  @prop senderNoteProof: SparseMerkleProof;
  @prop receiverNote: Note;
  @prop receiverNoteProof: SparseMerkleProof;

  constructor(
    senderNote: Note,
    senderNoteProof: SparseMerkleProof,
    receiverNote: Note,
    receiverNoteProof: SparseMerkleProof
  ) {
    super();
    this.senderNote = senderNote;
    this.senderNoteProof = senderNoteProof;
    this.receiverNote = receiverNote;
    this.receiverNoteProof = receiverNoteProof;
  }
}
