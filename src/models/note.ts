import {
  CircuitValue,
  Encryption,
  Field,
  isReady,
  Poseidon,
  PrivateKey,
  prop,
  PublicKey,
  UInt64,
} from 'snarkyjs';
import { EncryptedNote } from './encrypted_note';

await isReady;

export const DummyPrivateKey = PrivateKey.ofBits(Field.zero.toBits());

export class Note extends CircuitValue {
  @prop amount: UInt64;
  @prop owner: PublicKey;
  @prop memo: Field;
  @prop blinding: Field;

  constructor(
    amount: UInt64,
    owner: PublicKey,
    memo: Field,
    blinding: Field = Field.random()
  ) {
    super();
    this.amount = amount;
    this.owner = owner;
    this.memo = memo;
    this.blinding = blinding;
  }

  static empty(): Note {
    return new Note(UInt64.zero, PublicKey.empty(), Field.zero, Field.zero);
  }

  // toFields(): Field[] {
  //   return this.amount
  //     .toFields()
  //     .concat(this.owner.toFields())
  //     .concat(this.memo.toFields())
  //     .concat(this.blinding.toFields());
  // }

  hash(): Field {
    return Poseidon.hash(this.toFields());
  }

  encrypt(): EncryptedNote {
    const cipherText = Encryption.encrypt(this.toFields(), this.owner);

    return new EncryptedNote(cipherText);
  }

  getCommitment(): Field {
    return Poseidon.hash(this.toFields());
  }

  getNullifier(privateKey: PrivateKey): Field {
    const commitment = this.getCommitment();
    let sign = Poseidon.hash(privateKey.toFields());
    return Poseidon.hash([commitment].concat(sign.toFields()));
  }
}
