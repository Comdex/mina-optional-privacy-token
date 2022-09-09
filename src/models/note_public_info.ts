import { arrayProp, CircuitValue, Field, prop } from 'snarkyjs';
import { EncryptedNote } from './encrypted_note';

export class NotePublicInfo extends CircuitValue {
  @prop commitment: Field;
  @prop encryptedNote: EncryptedNote;

  constructor(commitment: Field, encryptedNote: EncryptedNote) {
    super();
    this.commitment = commitment;
    this.encryptedNote = encryptedNote;
  }

  static empty(): NotePublicInfo {
    return new NotePublicInfo(Field.zero, EncryptedNote.empty());
  }
}
