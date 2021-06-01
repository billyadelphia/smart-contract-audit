# The Salvation Coin (SALV) security audit. 
Conducted by a professional Blockchain Developer, Bily Putra B. [billyadelphia](https://github.com/billyadelphia) in June 2021.

## The Salvation Coin (SALV) Specificities
 - Symbol : SALV
 - Name : The Salvation Coin
 - Decimals : 9
 - Deployed At : https://bscscan.com/address/0x6A0b894EEF70E41411a8efBE7A75CF426Fdb0497#contracts
 - Source Code : https://bscscan.com/address/0x6A0b894EEF70E41411a8efBE7A75CF426Fdb0497#code
 - Disclosure policy : Public
 - Platform : Binance Smart Chain (BSC)
 - Number of lines : 1189

# The Salvation Coin (SALV) Smart Contract Security Audit Report
## *Are Your Funds Safe?*
### In Scope : SALV Solidity contract

# 2. Findings 
In total, n issues were reported including :
- 8 owner privileges (the ability of an owner to manipulate the contract).
- 3 transfer amount manipulation (the final amount that the recipient will receive might be changed based on tax and reward function).
- 2 external calls risk (External calls may execute malicious code in that contract or any other contract that it depends upon).
- 2 timestamp dependence risk (the timestamp of the block can be manipulated by the miner, and all direct and indirect uses of the timestamp should be considered).

## 2.1 Owner privileges
Severity: Owner Privileges.
Description:
 - Exclude addresses from receiving reward `excludeFromReward`. Addresses can be re-include again by the owner *(includeInReward).
 - Exclude addresses from receiving fee `excludeFromFee`. Addresses can be re-include again by the owner *(includeInFee).
 - Change the percentage of tax fee `setTaxFeePercent`.
 - Change the percentage of liquidity fee `setLiquidityFeePercent`.
 - Change the percentage of max token amount per transaction `setMaxTxPercent`.
 - Disable or enable the swap and liquify variable `setSwapAndLiquifyEnabled`.
 - Change the charity address `setCharityAddress`.
 - Ability to withdraw any BNB on the contract address to the recipient address `safeWithdrawBnb`.

## 2.2 Transfer amount manipulation
### Severity: Transfer amount manipulation.
### Description: 
- The sender cannot send SALV token more than max transaction amount `_maxTxAmount`.
- If the contract SALV balance is greater than 500 SALV (a constant number of SALV that will be add to the liquidity) and in swap and liquify variable is disabled and the sender is not the pair address and swap and liquify variable is enabled, then the contract will add new liquidity to the pair address by half of the amount of the SALV balance within the contract and also will burn quarter of SALV balance within the contract and also send some BNB worth of quarter of SALV balance within the contract to the contract address. 
Code Snippet :
```
 function _transfer(
       address from,
       address to,
       uint256 amount
   ) private {
       require(from != address(0), "ERC20: transfer from the zero address");
       require(to != address(0), "ERC20: transfer to the zero address");
       require(amount > 0, "Transfer amount must be greater than zero");
       if (from != owner() && to != owner())
           require(
               amount <= _maxTxAmount,
               "Transfer amount exceeds the maxTxAmount."
           );
 
       // is the token balance of this contract address over the min number of
       // tokens that we need to initiate a swap + liquidity lock?
       // also, don't get caught in a circular liquidity event.
       // also, don't swap & liquify if sender is uniswap pair.
       uint256 contractTokenBalance = balanceOf(address(this));
 
       if (contractTokenBalance >= _maxTxAmount) {
           contractTokenBalance = _maxTxAmount;
       }
 
       bool overMinTokenBalance =
           contractTokenBalance >= numTokensSellToAddToLiquidity;
       if (
           overMinTokenBalance &&
           !inSwapAndLiquify &&
           from != uniswapV2Pair &&
           swapAndLiquifyEnabled
       ) {
           contractTokenBalance = numTokensSellToAddToLiquidity;
 
           swapAndLiquify(contractTokenBalance.div(2));
           _tokenTransfer(
               address(this),
               burnAddress,
               contractTokenBalance.div(4),
               false
           );
           bnbTransfer(contractTokenBalance.div(4));
       }
 
       //indicates if fee should be deducted from transfer
       bool takeFee = true;
 
       //if any account belongs to _isExcludedFromFee account then remove the fee
       if (_isExcludedFromFee[from] || _isExcludedFromFee[to]) {
           takeFee = false;
       }
 
       //transfer amount, it will take tax, burn, liquidity fee
       _tokenTransfer(from, to, amount, takeFee);
   }
```
- If the sender or the recipient is not excluded from the fee `isExcludedFromFee` , then the amount that receipt gets will be decreased by the fee.

## 2.3 External calls risk
### Severity: Low severity calls to external DEX Router (PancakeSwap).
### Possible issue : Any transfer function related may fail due lack of liquidity.
### Description: 
- On `swapTokensForBnb`, the execution may fail due lack of liquidity.

Code Snippet 
```
       // make the swap    uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
           tokenAmount,
           0, // accept any amount of ETH
           path,
           address(this),
           block.timestamp
       );
```
- `addLiquidity` may fail due of lack of BNB balance.

Code Snippet
```
function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
       // approve token transfer to cover all possible scenarios
      _approve(address(this), address(uniswapV2Router), tokenAmount);
 
           // add the liquidity
           uniswapV2Router.addLiquidityETH{value: ethAmount}(
               address(this),
               tokenAmount,
               0, // slippage is unavoidable
               0, // slippage is unavoidable
               owner(),
               block.timestamp
           );
   }
```

Suggestion
``` 
function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
       // approve token transfer to cover all possible scenarios
       if(ethAmount >= address(this).balance){
           _approve(address(this), address(uniswapV2Router), tokenAmount);
           // add the liquidity
           uniswapV2Router.addLiquidityETH{value: ethAmount}(
               address(this),
               tokenAmount,
               0, // slippage is unavoidable
               0, // slippage is unavoidable
               owner(),
               block.timestamp);
}}
```
# 2.3 Timestamp dependence risk
## Severity: Timestamp dependence.
## Description: 
- On `swapTokensForBnb`, the execution may fail due lack of invalid deadline.

Code Snippet 
```
   function swapTokensForBnb(uint256 tokenAmount) private {
       // generate the uniswap pair path of token -> weth
       address[] memory path = new address[](2);
       path[0] = address(this);
       path[1] = uniswapV2Router.WETH();
 
       _approve(address(this), address(uniswapV2Router), tokenAmount);
 
       // make the swap
       uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
           tokenAmount,
           0, // accept any amount of ETH
           path,
           address(this),
           block.timestamp
       );
   }
```
Suggestion 
```
   function swapTokensForBnb(uint256 tokenAmount) private {
       // generate the uniswap pair path of token -> weth
       address[] memory path = new address[](2);
       path[0] = address(this);
       path[1] = uniswapV2Router.WETH();
 
       _approve(address(this), address(uniswapV2Router), tokenAmount);
 
       // make the swap
       uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
           tokenAmount,
           0, // accept any amount of ETH
           path,
           address(this),
           block.timestamp + 300 // add 5 minutes more for delay
       );
   }
```
- On `addLiquidity`, the execution may fail due lack of invalid deadline.

Code Snippet 
```
   function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
       // approve token transfer to cover all possible scenarios
       if (ethAmount >= address(this).balance) {
           _approve(address(this), address(uniswapV2Router), tokenAmount);
 
           // add the liquidity
           uniswapV2Router.addLiquidityETH{value: ethAmount}(
               address(this),
               tokenAmount,
               0, // slippage is unavoidable
               0, // slippage is unavoidable
               owner(),
               block.timestamp
           );
       }
   }
```

Suggestion 
```
   function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
       // approve token transfer to cover all possible scenarios
       if (ethAmount >= address(this).balance) {
           _approve(address(this), address(uniswapV2Router), tokenAmount);
 
           // add the liquidity
           uniswapV2Router.addLiquidityETH{value: ethAmount}(
               address(this),
               tokenAmount,
               0, // slippage is unavoidable
               0, // slippage is unavoidable
               owner(),
               block.timestamp + 300 // add 5 minutes more for delay
           );
       }
   }
```

