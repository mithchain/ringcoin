// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RING_PRIMITIVES_BLOCK_H
#define RING_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;
    std::string diamondIdentifier;

    CBlockHeader()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->nVersion);
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
        READWRITE(nTime);
        READWRITE(nBits);
        READWRITE(nNonce);
        READWRITE(diamondIdentifier);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
        diamondIdentifier.clear();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;
    uint256 GetPowHash() const;         // Ring-fork: Seperate block hash and pow hash
    static uint256 MinotaurHashArbitrary(const char *data); // Ring-fork: Hash arbitrary data with Minotaur

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    // Ring-fork: Hive: Check if this block is hivemined
    bool IsHiveMined(const Consensus::Params& consensusParams) const {
        return (nNonce == consensusParams.hiveNonceMarker);
    }

    // Ring-fork: Pop: Check if this block is popmined
    bool IsPopMined(const Consensus::Params& consensusParams) const {
        return (nNonce == consensusParams.popNonceMarker);
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;

    // memory only
    mutable bool fChecked;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
        diamondIdentifier = header.diamondIdentifier;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITEAS(CBlockHeader, *this);
        READWRITE(vtx);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        block.diamondIdentifier = diamondIdentifier;
        return block;
    }

    std::string ToString() const
    {
        std::stringstream s;
        s << "CBlock(hash=" << GetHash().ToString()
          << ", ver=0x" << std::hex << nVersion
          << ", hashPrevBlock=" << hashPrevBlock.ToString()
          << ", hashMerkleRoot=" << hashMerkleRoot.ToString()
          << ", nTime=" << nTime
          << ", nBits=" << nBits
          << ", nNonce=" << nNonce
          << ", diamondIdentifier=" << diamondIdentifier 
          << ", vtx=" << vtx.size() << ")\n";
        for (const auto& tx : vtx) {
            s << "  " << tx->ToString() << "\n";
        }
        return s.str();
    }
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(const std::vector<uint256>& vHaveIn) : vHave(vHaveIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // RING_PRIMITIVES_BLOCK_H
