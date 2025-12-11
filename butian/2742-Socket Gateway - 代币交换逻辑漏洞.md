# Socket Gateway - 代币交换逻辑漏洞

> **来源**: https://forum.butian.net/share/2742  
> **文章ID**: 2742

---

事件概述
----

2024年1月17日，Socket Gateway 由于 performAction 函数中代码逻辑出现错误，导致大约330万美元的损失

相关地址
----

攻击者地址: 0x50DF5a2217588772471B84aDBbe4194A2Ed39066

被攻击合约地址: 0x3a23F943181408EAC424116Af7b7790c94Cb97a5

漏洞合约地址: 0xCC5fDA5e3cA925bd0bb428C8b2669496eE43067e

攻击交易: 0xc6c3331fa8c2d30e1ef208424c08c039a89e510df2fb6ae31e5aa40722e28fd6

攻击合约地址: 0xf2D5951bB0A4d14BdcC37b66f919f9A1009C05d1

攻击过程
----

1.攻击者创建2个攻击合约

![](images/1705897202277-f86d1564-bc8e-47f1-85fc-f43e82cc1b38.png)

2.通过漏洞分别转移用户的 USDC, USDT, WETH, WBTC, DAI，MATIC

![](images/1705897312200-2259b71a-24c8-43ee-8125-667cc200675a.png)

3.将获取的代币全部转换为 ETH，获利约330万美金

![](images/1705897357937-170e8862-aedf-48b3-9920-c459d458fee8.png)

攻击分析
----

Socket Getway 的 Admin 在 1月13日执行了函数 addRoute 添加了新的 routeAddress

![](images/1705920309666-5475d6d9-80cd-4f04-9f2e-440a6b5e156f.png)

![](images/1705918989373-7e396b89-e548-4e7d-a7b2-d6eceef26980.png)

部署后进行了 ETH 与 WETH 的代币交换测试，漏洞出现在这个新部署的合约中的 performAction 函数中

![](images/1705919381266-3d42f97b-6987-48c5-b2ab-21bc0b6effe1.png)

在获利USDC的攻击交易 0xc6c3331fa8c2d30e1ef208424c08c039a89e510df2fb6ae31e5aa40722e28fd6 中

攻击者首先获取受害者的 USDC的余额和Socket Getway 中的批准数量

![](images/1705897660164-efa41c9a-ccc9-413e-b510-b4c8ce82f1b9.png)

然后通过控制 swapExtraData参数 操纵 calldata 调用 token的 transferfrom函数 将受批准的代币转移

```php
(bool success, ) = fromToken.call(swapExtraData);
```

![](images/1705898225578-bdd84a0c-ee6c-487d-a287-599e9649424f.png)

```php
function performAction(
        address fromToken,
        address toToken,
        uint256 amount,
        address receiverAddress,
        bytes32 metadata,
        bytes calldata swapExtraData
    ) external payable override returns (uint256) {
        uint256 _initialBalanceTokenOut;
        uint256 _finalBalanceTokenOut;

        // Swap Native to Wrapped Token
        if (fromToken == NATIVE_TOKEN_ADDRESS) {
            _initialBalanceTokenOut = ERC20(toToken).balanceOf(socketGateway);
            (bool success, ) = toToken.call{value: amount}(swapExtraData);

            if (!success) {
                revert SwapFailed();
            }

            _finalBalanceTokenOut = ERC20(toToken).balanceOf(socketGateway);

            require(
                (_finalBalanceTokenOut - _initialBalanceTokenOut) == amount,
                "Invalid wrapper contract"
            );

            // Send weth to user
            ERC20(toToken).transfer(receiverAddress, amount);
        } else {
            _initialBalanceTokenOut = address(socketGateway).balance;

            // Swap Wrapped Token To Native Token
            ERC20(fromToken).safeTransferFrom(
                msg.sender,
                socketGateway,
                amount
            );

            (bool success, ) = fromToken.call(swapExtraData);

            if (!success) {
                revert SwapFailed();
            }

            _finalBalanceTokenOut = address(socketGateway).balance;

            require(
                (_finalBalanceTokenOut - _initialBalanceTokenOut) == amount,
                "Invalid wrapper contract"
            );

            // send ETH to the user
            payable(receiverAddress).transfer(amount);
        }

        emit SocketSwapTokens(
            fromToken,
            toToken,
            amount,
            amount,
            Identifier,
            receiverAddress,
            metadata
        );

        return amount;
    }
```

代码功能主要是用于用户 WETH 与 ETH 的转换， 虽然没有检测 fromToken 与 toToken的地址，但由于检查了函数执行前后的代币数量，所以逻辑上是限定了传入 WETH地址

![](images/1705898481616-3e2f7a8f-b835-494c-a17f-6e22576affd3.png)

例如该功能的一笔正常交易, fromToken 与 toToken 应为 ETH 与 WETH 地址才会成功交易，否则无法通过代币数量检测![](images/1705920060295-c9b92bb4-4799-4860-bbbe-781232036f44.png)

```php
require(
          (_finalBalanceTokenOut - _initialBalanceTokenOut) == amount,
          "Invalid wrapper contract"
);
```

但如果传入 amout 参数为 0 时，就会导致 (\_finalBalanceTokenOut - \_initialBalanceTokenOut) == amount 恒通过，导致代币数量检测失效，这里再通过控制 fromToken 和 swapExtraData 就可以将其他用户批准的代币转移且无需转入ETH

![](images/1705900632742-7879cfa3-2901-4560-bb1b-51c483734869.png)

![](images/1705900213047-fd2b1f31-5430-4bb6-8a8e-258c0af5b98e.png)
