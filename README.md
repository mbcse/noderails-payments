# NodeRails

NodeRails is a non-custodial crypto payment infrastructure platform for
internet businesses, apps, and developers who want to accept crypto with
production-grade reliability and buyer protection.

Website: [https://www.noderails.com](https://www.noderails.com)  
Merchant app: [https://merchant.noderails.com](https://merchant.noderails.com)  
Docs: [https://www.noderails.com/docs](https://www.noderails.com/docs)

## What NodeRails provides

- Hosted checkout and payment links
- Checkout sessions and payment intents APIs
- Subscriptions and recurring billing
- Invoicing and payment status tracking
- Webhooks with signed payloads and retries
- Payout flows for merchant operations

## Non-custodial by design

NodeRails is built as a technology and orchestration layer, not a custody
holder. Funds are controlled by wallet ownership and smart-contract rules.
Payment funds move through on-chain escrow logic and settle to merchant wallets
according to contract state and dispute outcomes.

## Buyer protection, disputes, and refunds

NodeRails includes dispute and refund support to make crypto commerce safer for
both customers and merchants:

- Payments follow a clear lifecycle (`AUTHORIZED -> CAPTURED -> SETTLED`)
- Captured funds are held in escrow with timelock rules
- Disputes can be raised during the dispute window
- Outcomes are resolved transparently and enforced on-chain
- Refund support is built into the payment flow

This helps provide chargeback-like confidence while preserving crypto-native
settlement and transparency.

## Risk and compliance layer

NodeRails runs fraud risk and compliance checks in the background to reduce
manual operational burden, including wallet and transaction-level screening
workflows designed for production payment operations.

## This shared package

This folder contains public smart contracts used by the NodeRails payment
system (escrow, payout manager, interfaces, and timelock library), plus
Foundry build configuration.

The backend platform code, infrastructure, and operational systems are not
included in this shared package.

