# Fedimint Architecture

Fedimint is a modular framework for building federated financial applications. Its core implementation is a federated Chaumian e-cash mint backed by Bitcoin, with Lightning Network integration for instant payments.

---

## System Overview

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#b3d9ff', 'secondaryColor': '#ffd6b3', 'tertiaryColor': '#d4f5d4', 'primaryTextColor': '#333', 'lineColor': '#666'}}}%%
flowchart TB
    subgraph Clients["Clients"]
        CLI["fedimint-cli"]
        WASM["WASM Client"]
        App["App Client"]
    end

    subgraph Federation["Federation (3-of-4 example)"]
        G1["Guardian 1<br/><i>fedimintd</i>"]
        G2["Guardian 2<br/><i>fedimintd</i>"]
        G3["Guardian 3<br/><i>fedimintd</i>"]
        G4["Guardian 4<br/><i>fedimintd</i>"]
        G1 <--->|"AlephBFT<br/>P2P"| G2
        G2 <--->|"AlephBFT<br/>P2P"| G3
        G3 <--->|"AlephBFT<br/>P2P"| G4
        G4 <--->|"AlephBFT<br/>P2P"| G1
        G1 <--->|"AlephBFT<br/>P2P"| G3
        G2 <--->|"AlephBFT<br/>P2P"| G4
    end

    subgraph GW["Lightning Gateway"]
        GWD["gatewayd"]
        LN["Lightning Node<br/>(LDK / LND)"]
        GWD --- LN
    end

    BTC["Bitcoin Network"]

    Clients -->|"API<br/>(WS / Iroh / HTTP)"| Federation
    GW -->|"API<br/>(WS / Iroh / HTTP)"| Federation
    LN <-->|"Lightning<br/>Protocol"| ExtLN["Lightning Network"]
    Federation -->|"Watch / Peg-out"| BTC

    style Clients fill:#d4e6f1,stroke:#85c1e9,color:#333
    style Federation fill:#d5f5e3,stroke:#82e0aa,color:#333
    style GW fill:#fdebd0,stroke:#f5b041,color:#333
    style BTC fill:#fadbd8,stroke:#f1948a,color:#333
    style ExtLN fill:#fadbd8,stroke:#f1948a,color:#333
```

**Federations** are groups of guardians (typically 3-4) that jointly run BFT consensus, hold threshold key shares, and process transactions. **Clients** interact with guardians over pluggable transports. **Gateways** bridge federations to the Lightning Network.

---

## Components at a Glance

| Component | What it does | Deep dive |
|-----------|-------------|-----------|
| **Consensus** | AlephBFT-based session processing, transaction ordering, threshold signing | [consensus.md](consensus.md) |
| **Module System** | Extensible three-crate pattern for transaction types, state machines, and API endpoints | [modules.md](modules.md) |
| **Database** | Layered key-value abstraction with module isolation, optimistic transactions, and migrations | [database.md](database.md) |
| **Client** | Operation tracking, async state machines, redundant federation API queries | [client.md](client.md) |
| **Gateway** | Lightning bridge with per-federation clients, LNv2 hold-invoice payment flows | [gateway.md](gateway.md) |
| **Crypto & Encoding** | Deterministic binary encoding, HKDF secret derivation, DKG, backup/recovery | [crypto-and-encoding.md](crypto-and-encoding.md) |

---

## Crate Map

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'primaryColor': '#b3d9ff', 'secondaryColor': '#ffd6b3', 'tertiaryColor': '#d4f5d4', 'primaryTextColor': '#333', 'lineColor': '#666'}}}%%
flowchart TB
    subgraph Binaries["Binaries"]
        FMD["fedimintd"]
        FMCLI["fedimint-cli"]
        GWD["gatewayd"]
    end

    subgraph ServerLayer["Server Layer"]
        FS["fedimint-server"]
        FSC["fedimint-server-core"]
    end

    subgraph ClientLayer["Client Layer"]
        FC["fedimint-client"]
        FCM["fedimint-client-module"]
        FAC["fedimint-api-client"]
    end

    subgraph Core["Core"]
        FCORE["fedimint-core"]
        FENC["encoding / db / net / module"]
    end

    subgraph ModulesLayer["Modules"]
        MINT["mint<br/><i>common / client / server</i>"]
        WALLET["wallet<br/><i>common / client / server</i>"]
        LNV2["lnv2<br/><i>common / client / server</i>"]
        META["meta<br/><i>common / client / server</i>"]
    end

    subgraph Infra["Infrastructure"]
        CONN["fedimint-connectors"]
        RDB["fedimint-rocksdb"]
        DERIVE["fedimint-derive"]
        CRYPTO["crypto/derive-secret<br/>crypto/tbs"]
    end

    FMD --> FS
    FMCLI --> FC
    GWD --> FC

    FS --> FSC --> FCORE
    FC --> FCM --> FCORE
    FAC --> FCORE
    FC --> FAC
    FS --> FAC

    MINT & WALLET & LNV2 & META --> FSC
    MINT & WALLET & LNV2 & META --> FCM
    MINT & WALLET & LNV2 & META --> FCORE

    FCORE --> DERIVE & CRYPTO
    FS & FC --> CONN
    FS & FC --> RDB

    style Binaries fill:#d4e6f1,stroke:#85c1e9,color:#333
    style ServerLayer fill:#d5f5e3,stroke:#82e0aa,color:#333
    style ClientLayer fill:#fdebd0,stroke:#f5b041,color:#333
    style Core fill:#e8daef,stroke:#bb8fce,color:#333
    style ModulesLayer fill:#fdebd0,stroke:#f5b041,color:#333
    style Infra fill:#fadbd8,stroke:#f1948a,color:#333
```

### Layer Summary

- **Binaries** -- `fedimintd` (guardian daemon), `fedimint-cli` (client CLI), `gatewayd` (Lightning gateway)
- **Server Layer** -- `fedimint-server` runs consensus and hosts the guardian API; `fedimint-server-core` defines the `ServerModule` trait
- **Client Layer** -- `fedimint-client` manages operations and state machines; `fedimint-client-module` defines the `ClientModule` trait; `fedimint-api-client` handles federation communication
- **Core** -- `fedimint-core` provides shared types, encoding, database abstractions, networking primitives, and the module registry
- **Modules** -- Each module follows a `common / client / server` three-crate split (see [modules.md](modules.md))
- **Infrastructure** -- Transport connectors (Iroh, WS, HTTP), RocksDB backend, proc-macro derives, and cryptographic primitives (threshold blind signatures, HKDF)

---

## Entry Points

| Binary | Crate | Main |
|--------|-------|------|
| `fedimintd` | `fedimintd` | `fedimintd/src/bin/main.rs` |
| `fedimint-cli` | `fedimint-cli` | `fedimint-cli/src/main.rs` |
| `gatewayd` | `fedimint-gateway-server` | `gateway/fedimint-gateway-server/src/bin/main.rs` |
