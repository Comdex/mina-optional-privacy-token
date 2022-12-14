import {
  computeRootByFieldInCircuit,
  createEmptyValue,
  DeepSparseMerkleSubTree,
  SMT_EMPTY_VALUE,
  SparseMerkleProof,
  verifyProofByFieldInCircuit,
} from 'snarky-smt';
import {
  method,
  SmartContract,
  State,
  state,
  UInt64,
  Permissions,
  PublicKey,
  PrivateKey,
  Mina,
  AccountUpdate,
  Field,
  Experimental,
  Poseidon,
  Circuit,
  CircuitString,
  circuitValue,
  Bool,
  shutdown,
  isReady,
} from 'snarkyjs';
import { Commitments } from './models/commitments';
import { EncryptedNote } from './models/encrypted_note';
import { Note } from './models/note';
import { InputNoteInfos, OutputNotes } from './models/notes';
import { NoteInfo } from './models/note_info';
import { Operation } from './models/operation';

await isReady;

let doProofs = true;

let tokenSymbol = 'minacash';

class TokenContract extends SmartContract {
  @state(UInt64) MAX_SUPPLY = State<UInt64>();
  @state(UInt64) TOTAL_SUPPLY = State<UInt64>();
  // @state(UInt64) currentTokenBalance = State<UInt64>();
  @state(Field) notesCommitment = State<Field>();
  @state(Field) nullifiersCommitment = State<Field>();

  events = {
    Transfer: circuitValue<{ from: PublicKey; to: PublicKey; value: UInt64 }>({
      from: PublicKey,
      to: PublicKey,
      value: UInt64,
    }),
    Approval: circuitValue<{
      owner: PublicKey;
      spender: PublicKey;
      value: UInt64;
    }>({ owner: PublicKey, spender: PublicKey, value: UInt64 }),
    NewNote: NoteInfo,
    NewNullifier: Field,
  };

  deploy(args: {
    verificationKey?:
      | {
          data: string;
          hash: string | Field;
        }
      | undefined;
    zkappKey?: PrivateKey | undefined;
    tokenSymbol: string;
  }) {
    super.deploy(args);
    this.tokenSymbol.set(args.tokenSymbol);
    this.setPermissions({
      ...Permissions.default(),
      editState: Permissions.proofOrSignature(),
      receive: Permissions.proofOrSignature(),
    });
  }

  @method init(
    maxSupply: UInt64,
    totalSupply: UInt64,
    notesCommitment: Field,
    nullifiersCommitment: Field
  ) {
    this.MAX_SUPPLY.set(maxSupply);
    this.TOTAL_SUPPLY.set(totalSupply);
    this.notesCommitment.set(notesCommitment);
    this.nullifiersCommitment.set(nullifiersCommitment);

    totalSupply.assertLte(maxSupply);

    let address = this.self.body.publicKey;
    this.experimental.token.mint({
      address,
      amount: totalSupply,
    });

    // this.currentTokenBalance.set(totalSupply);
    // this.account.isNew.assertEquals(Bool(true));
    // this.balance.subInPlace(Mina.accountCreationFee());
  }

  @method mint(receiverAddress: PublicKey, amount: UInt64) {
    this.self.body.publicKey.equals(receiverAddress).assertFalse();

    let totalSupply = this.TOTAL_SUPPLY.get();
    this.TOTAL_SUPPLY.assertEquals(totalSupply);

    let maxSupply = this.MAX_SUPPLY.get();
    this.MAX_SUPPLY.assertEquals(maxSupply);

    let newTotalSupply = totalSupply.add(amount);

    newTotalSupply.assertLte(maxSupply);

    this.experimental.token.mint({
      address: receiverAddress,
      amount,
    });

    this.TOTAL_SUPPLY.set(newTotalSupply);
  }

  name(): CircuitString {
    return CircuitString.fromString('SomeCoin');
  }

  symbol(): CircuitString {
    return CircuitString.fromString('tokenSymbol');
  }

  totalSupply(): UInt64 {
    return this.TOTAL_SUPPLY.get();
  }

  @method
  transfer(
    senderAddress: PublicKey,
    receiverAddress: PublicKey,
    amount: UInt64
  ) {
    this.experimental.token.send({
      to: receiverAddress,
      from: senderAddress,
      amount,
    });
  }

  @method
  publicAccountTransferToShieldedAccount(
    senderAddress: PublicKey,
    receiverAddress: PublicKey,
    amount: UInt64,
    receiverNote: Note,
    nonMembershipProof: SparseMerkleProof
  ) {
    const notesCommitment = this.notesCommitment.get();
    this.notesCommitment.assertEquals(notesCommitment);

    let currentNoteCommitment = nonMembershipProof.root;
    currentNoteCommitment.assertEquals(notesCommitment);

    receiverNote.amount.assertEquals(amount);
    receiverNote.owner.assertEquals(receiverAddress);

    const commitment = receiverNote.getCommitment();
    const encryptedNote = receiverNote.encrypt();

    // non-membership proof verify
    verifyProofByFieldInCircuit(
      nonMembershipProof,
      currentNoteCommitment,
      Poseidon.hash([commitment]),
      SMT_EMPTY_VALUE
    ).assertTrue();

    this.experimental.token.send({
      to: this.address,
      from: senderAddress,
      amount: amount,
    });

    let noteInfo = new NoteInfo(commitment, encryptedNote);
    let newNotesCommitment = computeRootByFieldInCircuit(
      nonMembershipProof.sideNodes,
      Poseidon.hash([commitment]),
      Poseidon.hash(noteInfo.toFields())
    );
    this.notesCommitment.set(newNotesCommitment);

    this.emitEvent('NewNote', noteInfo);
  }

  @method
  shieldedAccountTransferToPublicAccount(
    senderAddress: PublicKey,
    receiverAddress: PublicKey,
    amount: UInt64,
    ownerKey: PrivateKey,
    inputNoteInfos: InputNoteInfos,
    outputNotes: OutputNotes
  ) {
    const notesCommitment = this.notesCommitment.get();
    this.notesCommitment.assertEquals(notesCommitment);
    let currNoteCommitment = inputNoteInfos.membershipProofs[0].root;
    currNoteCommitment.assertEquals(notesCommitment);

    const nullifiersCommitment = this.nullifiersCommitment.get();
    this.nullifiersCommitment.assertEquals(nullifiersCommitment);
    let currNullifierCommitment = inputNoteInfos.nullifierProofs[0].root;
    currNullifierCommitment.assertEquals(nullifiersCommitment);

    let inputNullifiers: Field[] = [];

    let inputNotesTotalAmount = UInt64.zero;
    let dummyNote = Note.empty();
    let deepSubTree = new DeepSparseMerkleSubTree(
      currNullifierCommitment,
      Field
    );

    for (let i = 0; i < inputNoteInfos.noteInfos.length; i++) {
      let currNote = inputNoteInfos.noteInfos[i].getNote(ownerKey);
      let nullifier = currNote.getNullifier(ownerKey);

      deepSubTree.addBranch(
        inputNoteInfos.nullifierProofs[i],
        nullifier,
        createEmptyValue(Field)
      );
      this.emitEvent('NewNullifier', nullifier);
      inputNullifiers.push(nullifier);

      let checkSender = currNote.owner.equals(senderAddress);

      // membership proof, prove note in the note tree.
      let membershipProof = inputNoteInfos.membershipProofs[i];
      let commitmentHash = Poseidon.hash([currNote.getCommitment()]);
      let valueHash = Poseidon.hash(currNote.toFields());

      let checkMembership = Circuit.if(
        currNote.equals(dummyNote),
        Bool(true),
        verifyProofByFieldInCircuit(
          membershipProof,
          currNoteCommitment,
          commitmentHash,
          valueHash
        )
      );

      // non-membership proof, prove note is not in the nullifier tree.
      let nonMembershipProof = inputNoteInfos.nullifierProofs[i];
      let nullifierHash = Poseidon.hash([nullifier]);
      let checkNullifer = Circuit.if(
        currNote.equals(dummyNote),
        Bool(true),
        verifyProofByFieldInCircuit(
          nonMembershipProof,
          currNullifierCommitment,
          nullifierHash,
          SMT_EMPTY_VALUE
        )
      );

      checkSender.and(checkMembership).and(checkNullifer).assertTrue();
      inputNotesTotalAmount = inputNotesTotalAmount.add(currNote.amount);
    }

    // check that there are no same nullifiers.
    for (let i = 0; i < inputNullifiers.length - 1; i++) {
      for (let j = i + 1; j < inputNullifiers.length; j++) {
        inputNullifiers[i].equals(inputNullifiers[j]).assertFalse();
      }
    }

    for (let i = 0; i < inputNullifiers.length; i++) {
      deepSubTree.update(inputNullifiers[i], Field.one);
    }

    let newNullifiersCommitment = deepSubTree.getRoot();
    this.nullifiersCommitment.set(newNullifiersCommitment);

    inputNotesTotalAmount.value.assertGte(amount.value);

    let senderNote = outputNotes.senderNote;
    let senderNoteCommitment = senderNote.getCommitment();
    let encryptedNote = senderNote.encrypt();
    senderNote.owner.assertEquals(senderAddress);
    let senderNoteInfo = new NoteInfo(senderNoteCommitment, encryptedNote);

    let outputNotesTotalAmount = senderNote.amount.add(
      outputNotes.receiverNote.amount
    );
    inputNotesTotalAmount.sub(amount).assertEquals(outputNotesTotalAmount);

    // calculate new notes root
    let newNotesCommitment = computeRootByFieldInCircuit(
      outputNotes.senderNoteProof.sideNodes,
      Poseidon.hash([senderNoteCommitment]),
      Poseidon.hash(senderNoteInfo.toFields())
    );
    this.notesCommitment.set(newNotesCommitment);

    this.experimental.token.send({
      to: receiverAddress,
      from: senderAddress,
      amount: amount,
    });

    this.emitEvent('NewNote', senderNoteInfo);
  }

  @method
  shieldedAccountTransferToShieldedAccount(
    senderAddress: PublicKey,
    receiverAddress: PublicKey,
    amount: UInt64,
    ownerKey: PrivateKey,
    inputNoteInfos: InputNoteInfos,
    outputNotes: OutputNotes
  ) {
    const notesCommitment = this.notesCommitment.get();
    this.notesCommitment.assertEquals(notesCommitment);
    let currNoteCommitment = inputNoteInfos.membershipProofs[0].root;
    currNoteCommitment.assertEquals(notesCommitment);

    const nullifiersCommitment = this.nullifiersCommitment.get();
    this.nullifiersCommitment.assertEquals(nullifiersCommitment);
    let currNullifierCommitment = inputNoteInfos.nullifierProofs[0].root;
    currNullifierCommitment.assertEquals(nullifiersCommitment);

    let inputNullifiers: Field[] = [];

    let inputNotesTotalAmount = UInt64.zero;
    let dummyNote = Note.empty();
    let deepSubTree = new DeepSparseMerkleSubTree(
      currNullifierCommitment,
      Field
    );

    for (let i = 0; i < inputNoteInfos.noteInfos.length; i++) {
      let currNote = inputNoteInfos.noteInfos[i].getNote(ownerKey);
      let nullifier = currNote.getNullifier(ownerKey);

      deepSubTree.addBranch(
        inputNoteInfos.nullifierProofs[i],
        nullifier,
        createEmptyValue(Field)
      );
      this.emitEvent('NewNullifier', nullifier);
      inputNullifiers.push(nullifier);

      let checkSender = currNote.owner.equals(senderAddress);

      // membership proof, prove note in the note tree.
      let membershipProof = inputNoteInfos.membershipProofs[i];
      let commitmentHash = Poseidon.hash([currNote.getCommitment()]);
      let valueHash = Poseidon.hash(currNote.toFields());

      let checkMembership = Circuit.if(
        currNote.equals(dummyNote),
        Bool(true),
        verifyProofByFieldInCircuit(
          membershipProof,
          currNoteCommitment,
          commitmentHash,
          valueHash
        )
      );

      // non-membership proof, prove note is not in the nullifier tree.
      let nonMembershipProof = inputNoteInfos.nullifierProofs[i];
      let nullifierHash = Poseidon.hash([nullifier]);
      let checkNullifer = Circuit.if(
        currNote.equals(dummyNote),
        Bool(true),
        verifyProofByFieldInCircuit(
          nonMembershipProof,
          currNullifierCommitment,
          nullifierHash,
          SMT_EMPTY_VALUE
        )
      );

      checkSender.and(checkMembership).and(checkNullifer).assertTrue();
      inputNotesTotalAmount = inputNotesTotalAmount.add(currNote.amount);
    }

    // check that there are no same nullifiers.
    for (let i = 0; i < inputNullifiers.length - 1; i++) {
      for (let j = i + 1; j < inputNullifiers.length; j++) {
        inputNullifiers[i].equals(inputNullifiers[j]).assertFalse();
      }
    }

    for (let i = 0; i < inputNullifiers.length; i++) {
      deepSubTree.update(inputNullifiers[i], Field.one);
    }

    let newNullifiersCommitment = deepSubTree.getRoot();
    this.nullifiersCommitment.set(newNullifiersCommitment);

    inputNotesTotalAmount.value.assertGte(amount.value);

    let senderNote = outputNotes.senderNote;
    let senderNoteCommitment = senderNote.getCommitment();
    let encryptedNote = senderNote.encrypt();
    senderNote.owner.assertEquals(senderAddress);
    let senderNoteInfo = new NoteInfo(senderNoteCommitment, encryptedNote);

    let receiverNote = outputNotes.receiverNote;
    let receiverNoteCommitment = receiverNote.getCommitment();
    let encryptedReceiverNote = receiverNote.encrypt();
    receiverNote.owner.assertEquals(receiverAddress);
    let receiverNoteInfo = new NoteInfo(
      receiverNoteCommitment,
      encryptedReceiverNote
    );

    let outputNotesTotalAmount = senderNote.amount.add(receiverNote.amount);
    inputNotesTotalAmount.assertEquals(outputNotesTotalAmount);

    this.experimental.token.send({
      to: receiverAddress,
      from: senderAddress,
      amount: amount,
    });

    // calculate new notes root
    let emptyNoteInfo = createEmptyValue(NoteInfo);
    let notesDeepSubTree = new DeepSparseMerkleSubTree(
      currNoteCommitment,
      NoteInfo
    );
    notesDeepSubTree.addBranch(
      outputNotes.senderNoteProof,
      senderNoteCommitment,
      emptyNoteInfo
    );
    notesDeepSubTree.addBranch(
      outputNotes.receiverNoteProof,
      receiverNoteCommitment,
      emptyNoteInfo
    );
    notesDeepSubTree.update(senderNoteCommitment, senderNoteInfo);
    notesDeepSubTree.update(receiverNoteCommitment, receiverNoteInfo);

    this.notesCommitment.set(notesDeepSubTree.getRoot());

    this.experimental.token.send({
      to: receiverAddress,
      from: senderAddress,
      amount: amount,
    });

    this.emitEvent('NewNote', senderNoteInfo);
  }
}

let local = Mina.LocalBlockchain();
Mina.setActiveInstance(local);
let feePayerKey = local.testAccounts[0].privateKey;
let callerKey = local.testAccounts[1].privateKey;
let zkappKey = PrivateKey.random();
let zkappAddress = zkappKey.toPublicKey();

async function test() {
  let zkapp = new TokenContract(zkappAddress);

  if (doProofs) {
    console.log('start compiling');
    console.time('compile');
    await TokenContract.compile();
    console.timeEnd('compile');
  }

  console.log('deploying');
  let tx = await local.transaction(feePayerKey, () => {
    AccountUpdate.fundNewAccount(feePayerKey);
    zkapp.deploy({ zkappKey, tokenSymbol });
    // zkapp.init(
    //   UInt64.fromNumber(10_000),
    //   UInt64.fromNumber(10_000),
    //   initCommitments,
    //   initCommitments
    // );
  });
  if (doProofs) {
    await tx.prove();
    tx.send();
  } else {
    tx.send();
  }

  console.log('deploy done');

  shutdown();
}

await test();
