import {
  arrayProp,
  Bool,
  Circuit,
  CircuitValue,
  Field,
  isReady,
} from 'snarkyjs';
import { MAX_INPUT_NOTES, MAX_OUTPUT_NOTEINFOS } from './notes';
import { NoteInfo } from './note_info';

await isReady;

export class Operation extends CircuitValue {
  @arrayProp(Field, MAX_INPUT_NOTES) nullifiers: Field[];
  @arrayProp(NoteInfo, MAX_OUTPUT_NOTEINFOS) noteInfos: NoteInfo[];

  constructor(nullifiers: Field[], noteInfos: NoteInfo[]) {
    super();
    this.nullifiers = nullifiers;

    for (let i = noteInfos.length; i < MAX_OUTPUT_NOTEINFOS; i++) {
      noteInfos.push(NoteInfo.empty());
    }
    this.noteInfos = noteInfos;
  }

  containSameNullifier(otherOperation: Operation): Bool {
    let noSameNullifier = Bool(true);

    for (let i = 0; i < this.nullifiers.length; i++) {
      for (let j = 0; j < otherOperation.nullifiers.length; j++) {
        const tempNoSameNullifier = Circuit.if(
          this.nullifiers[i].equals(otherOperation.nullifiers[j]),
          Bool(false),
          Bool(true)
        );
        noSameNullifier = noSameNullifier.and(tempNoSameNullifier);
      }
    }

    return noSameNullifier;
  }

  static onlyNoteInfos(...noteInfos: NoteInfo[]): Operation {
    let nullifiers = new Array(MAX_INPUT_NOTES).fill(Field.zero);

    for (let i = noteInfos.length; i < MAX_OUTPUT_NOTEINFOS; i++) {
      noteInfos.push(NoteInfo.empty());
    }

    return new Operation(nullifiers, noteInfos);
  }

  static empty(): Operation {
    let nullifiers = new Array(MAX_INPUT_NOTES).fill(Field.zero);
    let noteInfos = new Array(MAX_OUTPUT_NOTEINFOS).fill(NoteInfo.empty());
    return new Operation(nullifiers, noteInfos);
  }
}
