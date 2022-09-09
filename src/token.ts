import {
  computeRootByFieldInCircuit,
  DeepSparseMerkleSubTree,
  SMT_EMPTY_VALUE,
  SparseMerkleProof,
  verifyProofByFieldInCircuit,
} from 'snarky-smt';
import {
  DeployArgs,
  method,
  SmartContract,
  State,
  state,
  UInt64,
  Permissions,
  PublicKey,
  PrivateKey,
  Mina,
  Party,
  Field,
  Experimental,
  Poseidon,
  Circuit,
  CircuitString,
  AsFieldElements,
  circuitValue,
  Bool,
} from 'snarkyjs';
import { Commitments } from './models/commitments';
import { MerkleProofs } from './models/merkle_proofs';
import { Note } from './models/note';
import { InputNotes, OutputNotes } from './models/notes';
import { NotePublicInfo } from './models/note_public_info';
import { Operation } from './models/operation';

let reducerStorage = {
  getActions({ fromActionHash: Field }): Operation[][] {
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

  reducer = Experimental.Reducer({ actionType: Note });
  reducer2 = Experimental.Reducer({ actionType: Field });

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

    this.account.isNew.assertEquals(Bool(true));
    this.balance.subInPlace(Mina.accountCreationFee());
  }

  @method mint(receiverAddress: PublicKey, amount: UInt64) {
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

    const encryptedNote = receiverNote.encrypt();
    this.reducer.dispatch(Operation.newNote(commitment, encryptedNote));
  }

  @method
  shieldedAccountTransferToPublicAccount(
    senderAddress: PublicKey,
    receiverAddress: PublicKey,
    amount: UInt64,
    inputNotes: InputNotes,
    inputNotesMemebershipProofs: MerkleProofs,
    inputNotesNullifierProofs: MerkleProofs,
    outputNotes: OutputNotes
  ) {
    const notesCommitments = this.notesCommitments.get();
    this.notesCommitments.assertEquals(notesCommitments);
    let currNoteCommitment = inputNotesMemebershipProofs.proofs[0].root;
    notesCommitments.containsCommitment(currNoteCommitment).assertTrue();

    const nullifierCommitments = this.nullifiersCommitments.get();
    this.nullifiersCommitments.assertEquals(nullifierCommitments);
    let currNullifierCommitment = inputNotesNullifierProofs.proofs[0].root;
    nullifierCommitments
      .containsCommitment(currNullifierCommitment)
      .assertTrue();

    let inputNotesTotalAmount = UInt64.zero;

    let dummyNote = Note.empty();
    for (let i = 0; i < inputNotes.notes.length; i++) {
      let currNote = inputNotes.notes[i];
      let checkSender = currNote.owner.equals(senderAddress);

      // membership proof, prove note in the note tree.
      let membershipProof = inputNotesMemebershipProofs.proofs[i];
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
      let nonMembershipProof = inputNotesNullifierProofs.proofs[i];
      let nullifierHash = Poseidon.hash([currNote.getNullifier()]);
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
      this.reducer.dispatch(Operation.newNullifier(currNote.getNullifier()));
    }

    inputNotesTotalAmount.value.assertGte(amount.value);

    let senderNote = outputNotes.senderNote;
    senderNote.owner.assertEquals(senderAddress);
    this.reducer.dispatch(
      Operation.newNote(senderNote.getCommitment(), senderNote.encrypt())
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
  }

  @method
  shieldedAccountTransferToShieldedAccount(
    senderAddress: PublicKey,
    receiverAddress: PublicKey,
    amount: UInt64,
    inputNotes: InputNotes,
    inputNotesMemebershipProofs: MerkleProofs,
    inputNotesNullifierProofs: MerkleProofs,
    outputNotes: OutputNotes
  ) {
    const notesCommitments = this.notesCommitments.get();
    this.notesCommitments.assertEquals(notesCommitments);
    let currNoteCommitment = inputNotesMemebershipProofs.proofs[0].root;
    notesCommitments.containsCommitment(currNoteCommitment).assertTrue();

    const nullifierCommitments = this.nullifiersCommitments.get();
    this.nullifiersCommitments.assertEquals(nullifierCommitments);
    let currNullifierCommitment = inputNotesNullifierProofs.proofs[0].root;
    nullifierCommitments
      .containsCommitment(currNullifierCommitment)
      .assertTrue();

    let inputNotesTotalAmount = UInt64.zero;

    let dummyNote = Note.empty();
    for (let i = 0; i < inputNotes.notes.length; i++) {
      let currNote = inputNotes.notes[i];
      let checkSender = currNote.owner.equals(senderAddress);

      // membership proof, prove note in the note tree.
      let membershipProof = inputNotesMemebershipProofs.proofs[i];
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
      let nonMembershipProof = inputNotesNullifierProofs.proofs[i];
      let nullifierHash = Poseidon.hash([currNote.getNullifier()]);
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
      this.reducer.dispatch(Operation.newNullifier(currNote.getNullifier()));
    }

    inputNotesTotalAmount.value.assertGte(amount.value);

    let senderNote = outputNotes.senderNote;
    senderNote.owner.assertEquals(senderAddress);
    this.reducer.dispatch(
      Operation.newNote(senderNote.getCommitment(), senderNote.encrypt())
    );

    let receiverNote = outputNotes.receiverNote;
    receiverNote.owner.assertEquals(receiverAddress);
    this.reducer.dispatch(
      Operation.newNote(receiverNote.getCommitment(), receiverNote.encrypt())
    );

    let outputNotesTotalAmount = senderNote.amount.add(receiverNote.amount);
    inputNotesTotalAmount.assertEquals(outputNotesTotalAmount);

    this.experimental.token.send({
      to: receiverAddress,
      from: senderAddress,
      amount: amount,
    });
  }

  @method
  rollupShieldedTxs() {
    const notesCommitments = this.notesCommitments.get();
    this.notesCommitments.assertEquals(notesCommitments);

    const nullifiersCommitments = this.nullifiersCommitments.get();
    this.nullifiersCommitments.assertEquals(nullifiersCommitments);

    const accumulatedOperations = this.accumulatedOperations.get();
    this.accumulatedOperations.assertEquals(accumulatedOperations);

    let pendingActions = reducerStorage.getActions({
      fromActionHash: accumulatedOperations,
    });

    // let subTree = new DeepSparseMerkleSubTree();
    // pendingActions.forEach((operations) => {
    //   operations.forEach((operation) => {});
    // });

    // let { state: newNotesCommitment, actionsHash: newAccumulatedOperations } =
    //   this.reducer.reduce(
    //     pendingActions,
    //     Field,
    //     (state: Field, operation: Operation) => {
    //       let newNotesCommitment = computeRootByFieldInCircuit(
    //         operation.witness,
    //         Poseidon.hash([operation.newNote.commitment]),
    //         operation.newNote.encryptedNote.hash()
    //       );

    //       return Circuit.if(operation.isNewNote(), newNotesCommitment, state);
    //     },
    //     // initial state
    //     { state: notesCommitment, actionsHash: accumulatedOperations }
    //   );
  }

  @method setInvalidTokenSymbol() {
    this.tokenSymbol.set(
      'this-token-symbol-is-too-long-and-will-cause-an-error'
    );
  }
}

let zkappKey: PrivateKey;
let zkappAddress: PublicKey;
let zkapp: TokenContract;
let feePayer: PrivateKey;

let tokenAccount1Key: PrivateKey;
let tokenAccount1: PublicKey;

let tokenAccount2Key: PrivateKey;
let tokenAccount2: PublicKey;

// Call `setupLocal` before running each test to reset the ledger state.
async function setupLocal() {
  // Set up local blockchain, create zkapp keys, token account keys, deploy the contract
  let Local = Mina.LocalBlockchain();
  Mina.setActiveInstance(Local);
  feePayer = Local.testAccounts[0].privateKey;

  zkappKey = PrivateKey.random();
  zkappAddress = zkappKey.toPublicKey();
  zkapp = new TokenContract(zkappAddress);

  tokenAccount1Key = Local.testAccounts[1].privateKey;
  tokenAccount1 = tokenAccount1Key.toPublicKey();

  tokenAccount2Key = Local.testAccounts[2].privateKey;
  tokenAccount2 = tokenAccount2Key.toPublicKey();

  (
    await Mina.transaction(feePayer, () => {
      Party.fundNewAccount(feePayer);
      zkapp.deploy({ zkappKey });
      zkapp.init();
    })
  ).send();
}
