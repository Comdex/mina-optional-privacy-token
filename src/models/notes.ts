import { arrayProp, CircuitValue, prop } from 'snarkyjs';
import { Note } from './note';

const MAX_INPUT_NOTES = 8;
const MAX_OUTPUT_NOTES = 2;

export class InputNotes extends CircuitValue {
  @arrayProp(Note, MAX_INPUT_NOTES) notes: Note[];

  constructor(notes: Note[]) {
    super();
    this.notes = notes;
  }
}

export class OutputNotes extends CircuitValue {
  @prop senderNote: Note;
  @prop receiverNote: Note;

  constructor(senderNote: Note, receiverNote: Note) {
    super();
    this.senderNote = senderNote;
    this.receiverNote = receiverNote;
  }
}
