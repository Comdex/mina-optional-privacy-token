import {
  arrayProp,
  CircuitValue,
  Encryption,
  Field,
  Group,
  isReady,
  Poseidon,
  PrivateKey,
  prop,
} from 'snarkyjs';
import { Note } from './note';

await isReady;

export const NOTE_CIPHERTEXT_LENGTH = 5 + 1;

export class EncryptedNote extends CircuitValue {
  @prop publicKey: Group;
  @arrayProp(Field, NOTE_CIPHERTEXT_LENGTH) cipherText: Field[];

  constructor(v: { publicKey: Group; cipherText: Field[] }) {
    super();
    this.publicKey = v.publicKey;
    this.cipherText = v.cipherText;
  }

  hash(): Field {
    return Poseidon.hash(this.toFields());
  }

  static empty(): EncryptedNote {
    return new EncryptedNote({
      publicKey: Group.ofFields([Field.zero, Field.zero]),
      cipherText: new Array(NOTE_CIPHERTEXT_LENGTH).fill(Field.zero),
    });
  }

  decrypt(privateKey: PrivateKey): Note {
    let newCipherText = this.cipherText.map((v) => v);
    const dataFields = Encryption.decrypt(
      { publicKey: this.publicKey, cipherText: newCipherText },
      privateKey
    );

    return Note.ofFields(dataFields);
  }
}
