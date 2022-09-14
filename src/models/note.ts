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
  @prop ownerPrivateKey: PrivateKey;

  constructor(
    amount: UInt64,
    owner: PublicKey,
    memo: Field,
    ownerPrivateKey: PrivateKey,
    blinding: Field = Field.random()
  ) {
    super();
    this.amount = amount;
    this.owner = owner;
    this.memo = memo;
    this.blinding = blinding;
    this.ownerPrivateKey = ownerPrivateKey;
  }

  static empty(): Note {
    return new Note(
      UInt64.zero,
      PublicKey.empty(),
      Field.zero,
      DummyPrivateKey,
      Field.zero
    );
  }

  toFields(): Field[] {
    return this.amount
      .toFields()
      .concat(this.owner.toFields())
      .concat(this.memo.toFields())
      .concat(this.blinding.toFields());
  }

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

  getNullifier(): Field {
    const commitment = this.getCommitment();
    let sign = Poseidon.hash(this.ownerPrivateKey!.toFields());
    return Poseidon.hash([commitment].concat(sign.toFields()));
  }
}
