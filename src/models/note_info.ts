import { CircuitValue, Field, isReady, prop } from 'snarkyjs';
import { EncryptedNote } from './encrypted_note';

await isReady;

export class NoteInfo extends CircuitValue {
  @prop commitment: Field;
  @prop encryptedNote: EncryptedNote;

  constructor(commitment: Field, encryptedNote: EncryptedNote) {
    super();
    this.commitment = commitment;
    this.encryptedNote = encryptedNote;
  }

  static empty(): NoteInfo {
    return new NoteInfo(Field.zero, EncryptedNote.empty());
  }
}
