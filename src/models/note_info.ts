import { CircuitValue, Field, isReady, PrivateKey, prop } from 'snarkyjs';
import { EncryptedNote } from './encrypted_note';
import { Note } from './note';

await isReady;

export class NoteInfo extends CircuitValue {
  @prop commitment: Field;
  @prop encryptedNote: EncryptedNote;

  constructor(commitment: Field, encryptedNote: EncryptedNote) {
    super();
    this.commitment = commitment;
    this.encryptedNote = encryptedNote;
  }

  getNote(privateKey: PrivateKey): Note {
    return this.encryptedNote.decrypt(privateKey);
  }

  static empty(): NoteInfo {
    return new NoteInfo(Field.zero, EncryptedNote.empty());
  }
}
