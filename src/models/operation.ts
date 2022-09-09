import { Bool, CircuitValue, Field, prop } from 'snarkyjs';
import { EncryptedNote } from './encrypted_note';
import { NotePublicInfo } from './note_public_info';

export class Operation extends CircuitValue {
  @prop newNullifier: Field;
  @prop newNote: NotePublicInfo;

  constructor(newNullifier: Field, newNote: NotePublicInfo) {
    super();
    this.newNullifier = newNullifier;
    this.newNote = newNote;
  }

  isNewNote(): Bool {
    return this.newNullifier.equals(Field.zero);
  }

  static newNullifier(nullifier: Field): Operation {
    return new Operation(nullifier, NotePublicInfo.empty());
  }

  static newNote(commitment: Field, encryptedNote: EncryptedNote): Operation {
    return new Operation(
      Field.zero,
      new NotePublicInfo(commitment, encryptedNote)
    );
  }
}
