---
title: PasswordStore Protocol Audit Report
author: 0xbl4ckwlf
date: December 20, 2023
header-includes:
  - \usepackage{titling}
  - \usepackage{graphicx}
---

<img src= "0xbl4ck.jpeg" alt="0xbl4ckwlf" title="0xbl4ck.jpeg" />


Prepared by: [0xbl4ckwlf](https://github.com/0xbl4ckwlf)
Lead Security Researcher: 
- 0xbl4ckwlf

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues found](#issues-found)
  - [Findings](#findings)
  - [High](#high)
    - [\[H-1\] Storing the password on chain makes it visible to anyone and no longer private](#h-1-storing-the-password-on-chain-makes-it-visible-to-anyone-and-no-longer-private)
    - [\[H-2\] `PasswordStore::setPassword` has no access controls, meaning a non-owner could change the password.](#h-2-passwordstoresetpassword-has-no-access-controls-meaning-a-non-owner-could-change-the-password)
  - [Informational](#informational)
    - [\[I-1\] The 'PasswordStore::getPassword' natspec indicates a parameter that dosn't exist, causing natspec to be incorrect.](#i-1-the-passwordstoregetpassword-natspec-indicates-a-parameter-that-dosnt-exist-causing-natspec-to-be-incorrect)

# Protocol Summary

Password Store is a protocol dedicated to storage and retrieval of a user's passwords. The protocol is designed to be used b a single user and is notdesigned to be used by multiple users. Only the owner should be able to set and access this password. 

# Disclaimer

The `0xbl4ckwlf` team makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security audit by the team is not an endorsement of the underlying business or product. The audit was time-boxed and the review of the code was solely on the security aspects of the Solidity implementation of the contracts.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity. See the documentation for more details.

# Audit Details 

**The finding described in this document corresponds with the following commit hash:**
```
2e8f81e263b3a9d18fab4fb5c46805ffc10a9990
```

## Scope 

```
./src/
#--- PasswordStore.sol
```
- Solc Version: 0.8.18
- Chain(s) to deploy contract to: Ethereum
  

## Roles

- Owner: The user who can set the password and read the password
- Outsiders: No one else should be able to set or read the password
  
# Executive Summary
## Issues found

| Severity | Number of issues found |
| -------- | ---------------------- |
| High     | 2                      |
| Medium   | 0                      |
| Low      | 0                      |
| Info     | 1                      |
| Total    | 3                      |

## Findings
The codebase contained a few vulnerabilities of which two of them are `HIGHs` and one other informational vulnerablity which has no effect so to speak but shows a complete disregard for the  NatSpec.
The codebase was tested and the vulnerabilities have been confirmed, the findings are fully itemised below.

## High
### [H-1] Storing the password on chain makes it visible to anyone and no longer private

**Description:** All data stored on chain is visible to anyone and can be read directly from the blockchain. The `PaswordStore: :s_password` variable is intended to be a private variable and only accessed through the `PasswordStore::getPassword` function, which is intended to be called by the owner of the contract. 

I can show one of such method of reading any data off chain below.


**Impact:** Anyone can read the private password, severely breaking the functionality of the protocol. 


**Proof of Concept:** (Proof of code)

The below test ccase shows how anyone can read the password directly from the blockchain

1. Create a locally running chain
```bash
make anvil
```

2. Deploy the contract to the chain
```
make deploy
```
3. Run the storage tool
We used '1'because that's the storage slot of `s_password` in the contract.

```
cast storage <ADDRESS_HERE> 1 --rpc-url http://127.0.0.1:8545
```

You'll get an output like this:

'0x6d7950617373776f726400000000000000000000000000000000000000000014'

You can then parse the hex to a string with:

```
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

And get an output of:
```
myPassword
```

**Recommended Mitigation:** Due to this, the overall architecture of this contract should be rethought. One could encrypt the password off-chain and then store the encrypted password on-chain. This would require the user to remember another password to decrypt the stored password. However, you're also likely to want to remove the view function as you wouldn't want the user to accidently send a transaction with this decryption key.


**Likelihood & Impact**
- Impact: HIGH
-Likelihood: HIGH
-Severity: HIGH



### [H-2] `PasswordStore::setPassword` has no access controls, meaning a non-owner could change the password.
 

**Description:** The `PasswordStore::setPassword` function is set to be an 'external' function, however, the natspec of the function and overall purpose of the smart contract is that 'This function allows only the owner to set a new password'.

```javascript

   function setPassword(string memory newPassword) external {
@>        //@audit - There are no access controls
        s_password = newPassword;
        emit SetNetPassword();
    }

```

**Impact:** Anyone can set/change the stored password, severely breaking the contract's intended functionality 

**Proof of Concept:** Add the following to the `PasswordStore.t.sol` test file

<details>
<summary>Code</summary>

```javascript
  function test_anyone_can_set_password(address randomAddress) public {
        vm.assume(randomAddress != owner);
        vm.prank(randomAddress);
        string memory expectedPassword = "myNewPassword";
        passwordStore.setPassword(expectedPassword);

        vm.prank(owner);
        string memory actualPassword = passwordStore.getPassword();
        assertEq(actualPassword, expectedPassword);
  }

```
</details>   



**Recommended Mitigation:** Add an access control conditional to  the `setPassword` function.

```javascript
if(msg.sender != s_owner){
    revert PasswordStore_NotOwner;
}

```

**Likelihoood & Impact**
-Impact: HIGH
-Likelihood: HIGH
-Severity: HIGH




## Informational

### [I-1] The 'PasswordStore::getPassword' natspec indicates a parameter that dosn't exist, causing natspec to be incorrect.


**Description:**

```javascript
  /*
     * @notice This allows only the owner to retrieve the password.
     // @audit there is no newPassword parameter!
     */
    function getPassword() external view returns (string memory) {
 
```

The `PasswordStore::getPassword` function signature is `getPassword()` which the natspec says it should be `getPassword(string)`.


**Impact:** The natspec is incorrect.


**Recommended Mitigation:** Remove the incorrect natspec line.

```diff
-    * @param newPassword The new password to set.
```

**Likelihoood & Impact**
-Impact: NONE
-Likelihood: HIGH
-Severity: Informational/Gas/Non-crits

NB: The above isn't essentially a bug but you should know...
