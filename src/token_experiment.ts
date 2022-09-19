import {
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

let reducerStorage = {
  getActions({
    fromActionHash,
    endActionHash,
  }: {
    fromActionHash?: Field;
    endActionHash?: Field;
  }): Operation[][] {
    return [] as Operation[][];
  },
};

class TokenContract extends SmartContract {
  @state(UInt64) MAX_SUPPLY = State<UInt64>();
  @state(UInt64) TOTAL_SUPPLY = State<UInt64>();
  // @state(UInt64) currentTokenBalance = State<UInt64>();
  @state(Commitments) notesCommitments = State<Commitments>();
  @state(Commitments) nullifiersCommitments = State<Commitments>();
  @state(Field) accumulatedOperations = State<Field>();

  reducer = Experimental.Reducer({ actionType: Operation });

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
  };

  proofStore: Map<string, SparseMerkleProof>;

  setProofStore(store: Map<string, SparseMerkleProof>) {
    this.proofStore = store;
  }

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
    notesCommitments: Commitments,
    nullifiersCommitments: Commitments
  ) {
    this.MAX_SUPPLY.set(maxSupply);
    this.TOTAL_SUPPLY.set(totalSupply);
    this.notesCommitments.set(notesCommitments);
    this.nullifiersCommitments.set(nullifiersCommitments);

    totalSupply.assertLte(maxSupply);

    let address = this.self.body.publicKey;
    this.experimental.token.mint({
      address,
      amount: totalSupply,
    });

    // this.currentTokenBalance.set(totalSupply);
    this.accumulatedOperations.set(Experimental.Reducer.initialActionsHash);

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
    const notesCommitments = this.notesCommitments.get();
    this.notesCommitments.assertEquals(notesCommitments);

    let currentNoteCommitment = nonMembershipProof.root;
    notesCommitments.containsCommitment(currentNoteCommitment).assertTrue();

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
    this.reducer.dispatch(Operation.onlyNoteInfos(noteInfo));
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
    const notesCommitments = this.notesCommitments.get();
    this.notesCommitments.assertEquals(notesCommitments);
    let currNoteCommitment = inputNoteInfos.membershipProofs[0].root;
    notesCommitments.containsCommitment(currNoteCommitment).assertTrue();

    const nullifierCommitments = this.nullifiersCommitments.get();
    this.nullifiersCommitments.assertEquals(nullifierCommitments);
    let currNullifierCommitment = inputNoteInfos.nullifierProofs[0].root;
    nullifierCommitments
      .containsCommitment(currNullifierCommitment)
      .assertTrue();

    let inputNullifiers: Field[] = [];

    let inputNotesTotalAmount = UInt64.zero;
    let dummyNote = Note.empty();
    for (let i = 0; i < inputNoteInfos.noteInfos.length; i++) {
      let currNote = inputNoteInfos.noteInfos[i].getNote(ownerKey);
      let nullifier = currNote.getNullifier(ownerKey);
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

    inputNotesTotalAmount.value.assertGte(amount.value);

    let senderNote = outputNotes.senderNote;
    senderNote.owner.assertEquals(senderAddress);
    let senderNoteInfo = new NoteInfo(
      senderNote.getCommitment(),
      senderNote.encrypt()
    );

    let outputNotesTotalAmount = senderNote.amount.add(
      outputNotes.receiverNote.amount
    );
    inputNotesTotalAmount.sub(amount).assertEquals(outputNotesTotalAmount);

    this.experimental.token.send({
      to: receiverAddress,
      from: senderAddress,
      amount: amount,
    });

    this.reducer.dispatch(new Operation(inputNullifiers, [senderNoteInfo]));
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
    const notesCommitments = this.notesCommitments.get();
    this.notesCommitments.assertEquals(notesCommitments);
    let currNoteCommitment = inputNoteInfos.membershipProofs[0].root;
    notesCommitments.containsCommitment(currNoteCommitment).assertTrue();

    const nullifierCommitments = this.nullifiersCommitments.get();
    this.nullifiersCommitments.assertEquals(nullifierCommitments);
    let currNullifierCommitment = inputNoteInfos.nullifierProofs[0].root;
    nullifierCommitments
      .containsCommitment(currNullifierCommitment)
      .assertTrue();

    let inputNullifiers: Field[] = [];

    let inputNotesTotalAmount = UInt64.zero;
    let dummyNote = Note.empty();
    for (let i = 0; i < inputNoteInfos.noteInfos.length; i++) {
      let currNote = inputNoteInfos.noteInfos[i].getNote(ownerKey);
      let nullifier = currNote.getNullifier(ownerKey);
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

    inputNotesTotalAmount.value.assertGte(amount.value);

    let senderNote = outputNotes.senderNote;
    senderNote.owner.assertEquals(senderAddress);
    let senderNoteInfo = new NoteInfo(
      senderNote.getCommitment(),
      senderNote.encrypt()
    );

    let receiverNote = outputNotes.receiverNote;
    receiverNote.owner.assertEquals(receiverAddress);
    let receiverNoteInfo = new NoteInfo(
      receiverNote.getCommitment(),
      receiverNote.encrypt()
    );

    let outputNotesTotalAmount = senderNote.amount.add(receiverNote.amount);
    inputNotesTotalAmount.assertEquals(outputNotesTotalAmount);

    this.experimental.token.send({
      to: receiverAddress,
      from: senderAddress,
      amount: amount,
    });

    this.reducer.dispatch(
      new Operation(inputNullifiers, [senderNoteInfo, receiverNoteInfo])
    );
  }

  @method
  rollupShieldedTxs(
    currNotesCommitment: Field,
    currNullifiersCommitment: Field
  ) {
    const notesCommitments = this.notesCommitments.get();
    this.notesCommitments.assertEquals(notesCommitments);
    notesCommitments.containsCommitment(currNotesCommitment);

    const nullifiersCommitments = this.nullifiersCommitments.get();
    this.nullifiersCommitments.assertEquals(nullifiersCommitments);
    nullifiersCommitments.containsCommitment(currNullifiersCommitment);

    const accumulatedOperations = this.accumulatedOperations.get();
    this.accumulatedOperations.assertEquals(accumulatedOperations);

    let pendingActions = reducerStorage.getActions({
      fromActionHash: accumulatedOperations,
    });

    let operations: Operation[] = [];
    let { actionsHash: newAccumulatedOperations } = this.reducer.reduce(
      pendingActions,
      Field,
      (state: Field, operation: Operation) => {
        operations.push(operation);
        return state;
      },
      // initial state
      { state: Field.zero, actionsHash: accumulatedOperations }
    );
    this.accumulatedOperations.set(newAccumulatedOperations);

    let legalOperations: Operation[] = [];
    let emptyOperation = Operation.empty();
    for (let i = 0; i < operations.length - 1; i++) {
      let operation = operations[i];
      for (let j = i + 1; j < operations.length; j++) {
        operation = Circuit.if(
          operation.containSameNullifier(operations[j]),
          emptyOperation,
          operation
        );
      }

      legalOperations.push(operation);
    }
    legalOperations.push(operations[operations.length - 1]);

    let notesSubTree = new DeepSparseMerkleSubTree<Field, EncryptedNote>(
      currNotesCommitment,
      EncryptedNote
    );
    let nullifiersSubTree = new DeepSparseMerkleSubTree<Field, Field>(
      currNullifiersCommitment,
      Field
    );
    legalOperations.forEach((v) => {
      let nullifiers = v.nullifiers;
      nullifiers.forEach((n) => {
        let proof: SparseMerkleProof = Circuit.witness(
          SparseMerkleProof,
          () => {
            return this.proofStore.get(n.toString())!;
          }
        );
        nullifiersSubTree.addBranch(proof, n, SMT_EMPTY_VALUE);
      });

      let noteInfos = v.noteInfos;
      noteInfos.forEach((noteInfo) => {
        let proof: SparseMerkleProof = Circuit.witness(
          SparseMerkleProof,
          () => {
            return this.proofStore.get(noteInfo.commitment.toString())!;
          }
        );
        notesSubTree.addBranch(
          proof,
          noteInfo.commitment,
          createEmptyValue(EncryptedNote)
        );
      });
    });

    legalOperations.forEach((v) => {
      let nullifiers = v.nullifiers;
      nullifiers.forEach((n) => {
        nullifiersSubTree.update(n, Field.one);
      });

      let noteInfos = v.noteInfos;
      noteInfos.forEach((noteInfo) => {
        notesSubTree.update(noteInfo.commitment, noteInfo.encryptedNote);
      });
    });

    let newNullifiersCommitment = nullifiersSubTree.getRoot();
    nullifiersCommitments.updateLatestCommitment(newNullifiersCommitment);
    this.nullifiersCommitments.set(nullifiersCommitments);

    let newNotesCommitment = notesSubTree.getRoot();
    notesCommitments.updateLatestCommitment(newNotesCommitment);
    this.notesCommitments.set(notesCommitments);
  }

  // @method setInvalidTokenSymbol() {
  //   this.tokenSymbol.set(
  //     'this-token-symbol-is-too-long-and-will-cause-an-error'
  //   );
  // }
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

  const initCommitments = Commitments.createInitCommitments();

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
