// Copyright (c) 2025 The Dwarfchain Developers
// Copyright (c) 2018-2019 The Ring Developers
// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <consensus/consensus.h>    // Ring-fork: For COINBASE_MATURITY
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

// Note: The Ring genesis block reward is unspendable. Its scriptpubkey is an embedded 32x32 8-bit raw image; decoding it is left as an exercise to the reader :)
#define GENESIS_HASH        "0xbcc41094e6da9f00f46edbc89d8659191697dfb384c2c729c76dab4c196bf7c4"
#define GENESIS_NONCE       0
#define GENESIS_TIMESTAMP   1714627200
#define GENESIS_MERKLE      "0x66865b3ca73069fff68a0ea8dd001bdcab641ee21171cba3e6af072c7ef4eded"
#define GENESIS_STRING      "The world’s first Ring and Diamond dual-coin blockchain is born."
#define GENESIS_IMAGE       "89504E470D0A1A0A0000000D4948445200000020000000200800000000561125280000000467414D410000B18F0BFC6105000000206348524D00007A26000080840000FA00000080E8000075300000EA6000003A98000017709CBA513C00000002624B474400FF878FCCBF0000000970485973000015870000158701B219EEBA0000000774494D4507E307140D2810796DF2C90000031C4944415438CB2D914D6F1B5518469FE7BD77C6F638B19DA48DEDD4260A5584DA20151481C4062A10422AFC0F7E013F8B6D575D14169508422A9568F9688112689D90389DF86B66EC7B1F16657D3647E7D00300291AD8AE6B55141191A2648A043C0940…4581C9B3BB3C993F3C8ACD5ED0620957C5D9A20AE3FF0021C5AE38E74A222800000020744558744372656174696F6E54696D6500323031373A30323A31372032333A34303A3031F1B710F60000002574455874646174653A63726561746500323031392D30372D32305431333A34303A31362B30333A303067C362F30000002574455874646174653A6D6F6469667900323031392D30372D32305431333A34303A31362B30333A3030169EDA4F0000001874455874536F667477617265007061696E742E6E657420342E312E36FD4E09E80000001174455874536F75726365004E494B4F4E204433303068FC3E620000000049454E44AE426082"

#define LAST_ID_BLOCK_HASH  "0x8e170db7606e433f0c690275d5e5df09d8da02ef418515961cad484f757f0f1c"
#define LAST_ID_CHAINWORK   "0x96da10"
#define LAST_ID_HEIGHT      34522

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{    
    const char* pszTimestamp = GENESIS_STRING;
    const CScript genesisOutputScript = CScript() << OP_RETURN << ParseHex(GENESIS_IMAGE);
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        //consensus.nSubsidyHalvingInterval = 420000;   // Halve every 420,000 blocks
        //consensus.BIP16Exception = uint256S("0x0");   // No BIP16 exception on chain
        consensus.BIP34Height = 100;
        consensus.BIP34Hash = uint256();                // Not needed; activated on unforkable block below initial distro end
        consensus.BIP65Height = 1;                      // BIP65 & 66 active since start
        consensus.BIP66Height = 1;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 300;               // Targeting 1 pow block in this many seconds
        consensus.nExpectedBlockSpacing = 300;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 4740; // 80% required for UASF activation
        consensus.nMinerConfirmationWindow = 5925;
             
        // Ring-fork: General consensus fields
        consensus.powLimitInitialDistribution = uint256S("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");       // Lower-than-powLimit difficulty for initial distribution blocks only
        consensus.blockSubsidyPow = 128 * COIN;             // Miner rewards for each block type
        consensus.blockSubsidyHive = 1 * COIN;
        consensus.blockSubsidyPopPrivate = 1 * COIN;
        consensus.blockSubsidyPopPublic = 0.5 * COIN;

        // Ring-fork: Hive: Consensus Fields
        consensus.dwarfCost = 1 * COIN;                  // Cost of a dwarf
        consensus.dwarfCreationAddress = "RNGSummonADwarvenMiningArmyXYzDNsz";  // Unspendable address for dwarf creation
        consensus.dwarfGestationBlocks = 6;           // The number of blocks for a new dwarf to mature (approx 0.5 hours)
        consensus.dwarfLifespanBlocks = 1;              // The number of blocks a dwarf lives for after maturation 
        consensus.powLimitHive = uint256S("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // Highest (easiest) dwarf hash target
        consensus.minHiveCheckBlock = consensus.lastInitialDistributionHeight + 1;   // Don't bother checking below this height for Hive blocks (not used for consensus/validation checks, just efficiency when looking for potential DCTs)
        consensus.hiveBlockSpacingTarget = 5;               // Target Hive block frequency (1 out of this many Hive and pow blocks combined should be Hivemined)
        consensus.hiveBlockSpacingTargetTypical = 5;        // Observed Hive block frequency (1 out of this many Hive and pow blocks combined are observed to be Hive)
        consensus.hiveNonceMarker = 1;                      // Nonce marker for hivemined blocks
        consensus.minK = 2;                                 // Minimum chainwork scale for Hive blocks (see Hive whitepaper section 5)
        consensus.maxK = 16;                                // Maximum chainwork scale for Hive blocks (see Hive whitepaper section 5)
        consensus.maxHiveDiff = 0.000175;                   // Hive difficulty at which max chainwork bonus is awarded
        consensus.maxKPow = 5;                              // Maximum chainwork scale for PoW blocks
        consensus.powSplit1 = 0.00009;                      // Below this Hive difficulty threshold, PoW block chainwork bonus is halved
        consensus.powSplit2 = 0.00005;                      // Below this Hive difficulty threshold, PoW block chainwork bonus is halved again
        consensus.maxConsecutiveHiveBlocks = 1;             // Maximum hive blocks that can occur consecutively before a PoW block is required
        consensus.hiveDifficultyWindow = 10;                // How many blocks the SMA averages over in hive difficulty adjust

        // Ring-fork: Pop: Consensus fields
        consensus.popBlocksPerHive = 1;                     // Expected number of pop blocks per Hive block. Note that increasing this here is not enough to spawn additional games, etc; this is used for time estimations.
        consensus.popNonceMarker = 2;                       // Nonce marker for popmined blocks
        consensus.popMinPrivateGameDepth = COINBASE_MATURITY;                           // Private game source transactions must be at least this many blocks deep
        consensus.popMaxPrivateGameDepth = consensus.popMinPrivateGameDepth + 50;       // Private game source transactions must be at most this many blocks deep
        consensus.popMaxPublicGameDepth = consensus.popMaxPrivateGameDepth + 200;       // Public game source transactions must be at most this many blocks deep
        consensus.popScoreAdjustWindowSize = 12;            // Windows size for adjusting pop score target
        consensus.popMinScoreTarget = 90;                   // Min score target
        consensus.popMaxScoreTarget = 240;                  // Max score target

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S(LAST_ID_CHAINWORK);                  // At lastInitialDistributionHeight

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S(LAST_ID_BLOCK_HASH);                // At lastInitialDistributionHeight

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xfe;
        pchMessageStart[2] = 0x83;
        pchMessageStart[3] = 0x9a;
        nDefaultPort = 8312;
        nPruneAfterHeight = 100000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(GENESIS_TIMESTAMP, GENESIS_NONCE, 0x1e0ffff0, 1, 128 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S(GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(GENESIS_MERKLE));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        //vSeeds.emplace_back("xxxxx.xxxxx");
        vSeeds.emplace_back("144.172.122.15:8312");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);  // for R
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,81);  // for Z
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,175);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "rng";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {0, uint256S(GENESIS_HASH)},
                {consensus.lastInitialDistributionHeight, uint256S(LAST_ID_BLOCK_HASH)},  // Last initial distribution block
            }
        };

        chainTxData = ChainTxData{
            /* nTime    */ GENESIS_TIMESTAMP,
            /* nTxCount */ 0,
            /* dTxRate  */ 0.001
        };

        /* Allow fallback fee on mainnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        //consensus.nSubsidyHalvingInterval = 420000;   // Halve every 420,000 blocks
        //consensus.BIP16Exception = uint256S("0x0");   // No BIP16 exception on chain
        consensus.BIP34Height = 100;
        consensus.BIP34Hash = uint256();    // Not needed
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 300; // 300 secs
        consensus.nExpectedBlockSpacing = 300;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 75; // Require 75% of last 100 blocks to activate rulechanges
        consensus.nMinerConfirmationWindow = 100;              

        // Ring-fork: General consensus fields
        consensus.blockSubsidyPow = 128 * COIN;             // Miner rewards for each block type
        consensus.blockSubsidyHive = 1 * COIN;
        consensus.blockSubsidyPopPrivate = 1 * COIN;
        consensus.blockSubsidyPopPublic = 0.5 * COIN;

        // Ring-fork: Hive: Consensus Fields
        consensus.dwarfCost = 1 * COIN;                     // Cost of a dwarf
        consensus.dwarfCreationAddress = "SUmmonTheTestnetDwarvenArmyXaNdvvm";  // Unspendable address for dwarf creation
        consensus.dwarfGestationBlocks = 6;                 // The number of blocks for a new dwarf to mature (approx 0.5 hours)
        consensus.dwarfLifespanBlocks = 1;                  // The number of blocks a dwarf lives for after maturation 
        consensus.powLimitHive = uint256S("0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");  // Highest (easiest) dwarf hash target
        consensus.minHiveCheckBlock = consensus.lastInitialDistributionHeight + 1;   // Don't bother checking below this height for Hive blocks (not used for consensus/validation checks, just efficiency when looking for potential DCTs)
        consensus.hiveBlockSpacingTarget = 5;               // Target Hive block frequency (1 out of this many Hive and pow blocks combined should be Hivemined)
        consensus.hiveBlockSpacingTargetTypical = 5;        // Observed Hive block frequency (1 out of this many Hive and pow blocks combined are observed to be Hive)
        consensus.hiveNonceMarker = 1;                      // Nonce marker for hivemined blocks
        consensus.minK = 2;                                 // Minimum chainwork scale for Hive blocks (see Hive whitepaper section 5)
        consensus.maxK = 16;                                // Maximum chainwork scale for Hive blocks (see Hive whitepaper section 5)
        consensus.maxHiveDiff = 0.001;                      // Hive difficulty at which max chainwork bonus is awarded
        consensus.maxKPow = 5;                              // Maximum chainwork scale for PoW blocks
        consensus.powSplit1 = 0.0004;                       // Below this Hive difficulty threshold, PoW block chainwork bonus is halved
        consensus.powSplit2 = 0.0002;                       // Below this Hive difficulty threshold, PoW block chainwork bonus is halved again
        consensus.maxConsecutiveHiveBlocks = 1;             // Maximum hive blocks that can occur consecutively before a PoW block is required
        consensus.hiveDifficultyWindow = 5000;                // How many blocks the SMA averages over in hive difficulty adjust

        // Ring-fork: Pop: Consensus fields
        consensus.popBlocksPerHive = 1;                     // Expected number of pop blocks per Hive block. Note that increasing this here is not enough to spawn additional games, etc; this is used for time estimations.
        consensus.popNonceMarker = 2;                       // Nonce marker for popmined blocks
        consensus.popMinPrivateGameDepth = COINBASE_MATURITY;                           // Private game source transactions must be at least this many blocks deep
        consensus.popMaxPrivateGameDepth = consensus.popMinPrivateGameDepth + 50;       // Private game source transactions must be at most this many blocks deep
        consensus.popMaxPublicGameDepth = consensus.popMaxPrivateGameDepth + 200;       // Public game source transactions must be at most this many blocks deep
        consensus.popScoreAdjustWindowSize = 12;            // Windows size for adjusting pop score target
        consensus.popMinScoreTarget = 90;                   // Min score target
        consensus.popMaxScoreTarget = 240;                  // Max score target

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x1304303f1de");    // 5400

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x468f8ab3e6e257f7e21a0c330986e3fd70413a381e77ce16afbadabfd26b733a"); // 5400

        pchMessageStart[0] = 0xb2;
        pchMessageStart[1] = 0xc4;
        pchMessageStart[2] = 0xb7;
        pchMessageStart[3] = 0x93;
        nDefaultPort = 8313;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(GENESIS_TIMESTAMP, GENESIS_NONCE, 0x1e0ffff0, 1, 128 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();       
        assert(consensus.hashGenesisBlock == uint256S(GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(GENESIS_MERKLE));

        vFixedSeeds.clear();
        vSeeds.emplace_back("144.172.122.15:8313");
        
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,63); // For S
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,78); // For Y
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,238);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "trng";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {0, uint256S(GENESIS_HASH)},
                {consensus.lastInitialDistributionHeight, uint256S("0xf953639bd2fa1645d38806dd41d2c92a51b4b0957d12382992c17f76e93adda8")},
                {5400, uint256S("0x468f8ab3e6e257f7e21a0c330986e3fd70413a381e77ce16afbadabfd26b733a")}
            }
        };

        chainTxData = ChainTxData{
            /* nTime    */ 1582987997,
            /* nTxCount */ 5603,
            /* dTxRate  */ 0.029
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        //consensus.nSubsidyHalvingInterval = 128;      
        //consensus.BIP16Exception = uint256S("0x0");   // No BIP16 exception on chain
        consensus.BIP34Height = 100; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();    // Not needed
        consensus.BIP65Height = 1; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1; // BIP66 activated on regtest (Used in functional tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetSpacing = 5 * 60; // 5 minutes
        consensus.nExpectedBlockSpacing = 300;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 12;       // Faster than normal for regtest (12 instead of 2016)
        
        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateVersionBitsParametersFromArgs(args);

        genesis = CreateGenesisBlock(GENESIS_TIMESTAMP, GENESIS_NONCE, 0x1e0ffff0, 1, 128 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();       
        assert(consensus.hashGenesisBlock == uint256S(GENESIS_HASH));
        assert(genesis.hashMerkleRoot == uint256S(GENESIS_MERKLE));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                //{0, uint256S(GENESIS_HASH)},
            }
        };

        chainTxData = ChainTxData{
            /* nTime    */ GENESIS_TIMESTAMP,
            /* nTxCount */ 0,
            /* dTxRate  */ 0.001
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
