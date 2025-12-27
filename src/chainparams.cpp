// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Rwa Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <hash.h> // for signet block challenge hash
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

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

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "BBC: 15/Mar/2025, US had productive talks with Putin over Ukraine war, Trump says.";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    /*
    总量：130000000000亿
    预挖:    100000000000即1000亿
    出块时间： 1分钟
    初始奖励数： 10000
    减半时间： 3 年
    前3年每年挖51亿多
    */
    CMainParams() {
        strNetworkID = CBaseChainParams::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        //consensus.nSubsidyHalvingInterval = 210000;
        consensus.nSubsidyHalvingInterval = 1576800; /*三年减半，每分钟一个区块*/
        //consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP16Exception = uint256();
        //consensus.BIP34Height = 227931;
        consensus.BIP34Height = 0;
        //consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP34Hash = uint256();
        //consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP65Height = 0;
        //consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        consensus.BIP66Height = 0;
        //consensus.CSVHeight = 419328; // 000000000000000004a1b34462cb8aeebd5799177f7a29cf28f2d1961716b5b5
        consensus.CSVHeight = 0;
        //consensus.SegwitHeight = 481824; // 0000000000000000001c8018d9cb3b742ef25114f27563e3fc4a1902167f9893
        consensus.SegwitHeight = 0;
        //consensus.MinBIP9WarningHeight = 483840; // segwit activation height + miner confirmation window
        consensus.MinBIP9WarningHeight = 0;
        //consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        //consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetTimespan = 1 * 24 * 60 * 60; // 难度调整周期
        //consensus.nPowTargetSpacing = 10 * 60;         
        consensus.nPowTargetSpacing = 1 * 60;            // 目标出块时间
        consensus.fPowAllowMinDifficultyBlocks = false;  // 是否允许出最小难度的块
        consensus.fPowNoRetargeting = false;             // 是否允许难度调整
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016  软分叉激活门槛
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        //consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        //consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        //consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 709632; // Approximately November 12th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0;

        //consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000001fa4663bbbe19f82de910280");
        consensus.nMinimumChainWork = uint256();
        //consensus.defaultAssumeValid = uint256S("0x00000000000000000008a89e854d57e5667df88f1cdef6fde2fbca1de5b639ad"); // 691719
        consensus.defaultAssumeValid = uint256();

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */

        /*
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
        */
        
        //RWA 0x72776100
        pchMessageStart[0] = 0x72;
        pchMessageStart[1] = 0x77;
        pchMessageStart[2] = 0x61;
        pchMessageStart[3] = 0x00;

        nDefaultPort = 8333;

        nPruneAfterHeight = 100000;
        //m_assumed_blockchain_size = 350;
        m_assumed_blockchain_size = 10;
        //m_assumed_chain_state_size = 6;
        m_assumed_chain_state_size = 1;

        /*
		
		python genesis.py  -z "BBC: 15/Mar/2025, US had productive talks with Putin over Ukraine war, Trump says." -n 10000000 -t 1742126400 -b 0x1e0fffff -v 500000000000
		04ffff001d01044c524242433a2031352f4d61722f323032352c205553206861642070726f647563746976652074616c6b73207769746820507574696e206f76657220556b7261696e65207761722c205472756d7020736179732e
		algorithm: SHA256
		merkle hash: 5694e0b86d592596c4443fa62badaf08e760fe06056503851a8985655105e4a5
		pszTimestamp: BBC: 15/Mar/2025, US had productive talks with Putin over Ukraine war, Trump says.
		pubkey: 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
		time: 1742126400
		bits: 0x1e0fffff
		Searching for genesis hash..
		genesis hash found!
		nonce: 10100045
		genesis hash: 0000099bd865de77fb9b5feec657ac4ee3c5bc3f90f440cb3caafdb6880c9cf2				
		*/

        genesis = CreateGenesisBlock(1742126400, 10100045, 0x1e0fffff, 1, 5000 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0000099bd865de77fb9b5feec657ac4ee3c5bc3f90f440cb3caafdb6880c9cf2"));        
        assert(genesis.hashMerkleRoot == uint256S("5694e0b86d592596c4443fa62badaf08e760fe06056503851a8985655105e4a5"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as an addrfetch if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        /*
		vSeeds.emplace_back("seed.bitcoin.sipa.be"); // Pieter Wuille, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("dnsseed.bluematt.me"); // Matt Corallo, only supports x9
        vSeeds.emplace_back("dnsseed.bitcoin.dashjr.org"); // Luke Dashjr
        vSeeds.emplace_back("seed.bitcoinstats.com"); // Christian Decker, supports x1 - xf
        vSeeds.emplace_back("seed.bitcoin.jonasschnelli.ch"); // Jonas Schnelli, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("seed.btc.petertodd.org"); // Peter Todd, only supports x1, x5, x9, and xd
        vSeeds.emplace_back("seed.bitcoin.sprovoost.nl"); // Sjors Provoost
        vSeeds.emplace_back("dnsseed.emzy.de"); // Stephan Oeste
        vSeeds.emplace_back("seed.bitcoin.wiz.biz"); // Jason Maurice
		*/

        //vSeeds.emplace_back("150.242.231.142");


		vSeeds.emplace_back("150.242.231.236");
        vSeeds.emplace_back("150.242.231.186");
		vSeeds.emplace_back("150.242.231.200");
		vSeeds.emplace_back("18.190.176.88");	//aws
		vSeeds.emplace_back("110.40.44.59");
		vSeeds.emplace_back("116.198.39.1");
		vSeeds.emplace_back("43.242.202.162");
		vSeeds.emplace_back("113.83.147.147");
		vSeeds.emplace_back("182.43.68.150");
		vSeeds.emplace_back("182.43.64.195");
		vSeeds.emplace_back("113.95.132.105");
		vSeeds.emplace_back("43.242.202.162");
		vSeeds.emplace_back("38.207.179.59");
		vSeeds.emplace_back("110.40.44.59");
		vSeeds.emplace_back("116.198.39.1");
		vSeeds.emplace_back("3.16.25.74");		//aws
		vSeeds.emplace_back("18.217.78.126");	//aws

        vSeeds.emplace_back("10.8.1.177");
        vSeeds.emplace_back("10.8.1.196");

        /*
        vSeeds.emplace_back("10.0.0.10");
        vSeeds.emplace_back("10.0.0.101");
        */

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {0, uint256S("0000099bd865de77fb9b5feec657ac4ee3c5bc3f90f440cb3caafdb6880c9cf2")},
                {1, uint256S("000005bdd1cf92beb2160476b7b854a3d77a69b892490e7eb418180d77df42ea")},
                {2, uint256S("000001065bd6b282f4a15cb27bb513422c1cf26967d3b547daa39f425c15fef3")},
                {3, uint256S("00000eb3733f1c30a3cbc35d2624b41d19dda39ca6d53860cfe30aaabbe2623b")},
                {4, uint256S("000009898291c876d5ae06fcd56bcc535ca8218fdd73d1d6d8a41dfd8b946527")},
                {5, uint256S("000007ecd625f21f4d1b2ce3abc73212df3a17534ed32edd383ca216d1b1a730")},
                {10, uint256S("0000044c87e4882fc8d278bb3b0bf97748c58a51360755d12b2a6587f8ea67b9")},
                {11, uint256S("0000029f8f92bf5d00032795f8f6810c10e054be7be27d69db3fe3e22343f1bf")},
                {12, uint256S("000000ee2ad0cb33611b1504d91c03a45061a3db9fbd95d95e1d406629429e72")},
                {13, uint256S("000005d03421f77904d407a645fb627e5229b3c311770ba07c90dd00bf092eb6")},
                {14, uint256S("000004b2e5953a68515c106e9f6d8a4a203b464ca3adf209c7b8a61e6c86c660")},
                {15, uint256S("00000521703644169e94d7b5e6f50fccfb7ec66528846a0e60bdbc5307c66c0c")},
                {100, uint256S("00000cc3b1626fcf80bc7b3cf90c65c28b5624ab278c67b38cc8ac6a12afec66")},
                {101, uint256S("0000053d92839197390a315964dc1abbcf10b293e7c3887a1d52ca10f6eb92a1")},
                {102, uint256S("000006320bd4ce148819fa4f6d1769e8f8289b79a2f2f66b3cc6277ce728afb4")},
                {103, uint256S("00000554f5158778aa8f74b86cc9ab320cac5fc48cb4ee453cb572a809ed4d49")},
                {104, uint256S("000005d05c852093048b1f104cf6a2b8f902ba6c63a96c73d3406210a7f2ceac")},
                {105, uint256S("00000c58b4d79d3ddd4003769e1a20dde54bf7a69d8db16de189de3a870b35ed")},

                {1000, uint256S("000003d4dada46e2fa6a91701f6f79e30f2c347955d4b194435f00f9faff8941")},
                {2000, uint256S("000002e1d90856ac6622a34a3b261a4e5d07d1821063e11a68ab2563f78af29b")},
                {3000, uint256S("000000267f5c1cab4177730f3d2227bb425b47bd9876f65387ce0bd7657fa63e")},
                {4000, uint256S("0000015b418bebdd56bdaae7364ff4bc2cac3d5af967f3ceea534f77d43f4d3b")},
                {5000, uint256S("000000af4a69c6f8bb2dc00fa7ec0e1188bae032939ef540b1de07f7037b45c8")},
                {10000, uint256S("0000001b03e85e8723d693e8bf3701fc844a376100f70268dbd17dc325151be8")},
                {20000, uint256S("00000000183a0896222b5485492bc94b341b0fa75e6fa30b723d1268d3d097e1")},
                {30000, uint256S("000000001da04b01996d8764238ffbf11a34072339e09fefc8db90e819c1ac86")},
                {40000, uint256S("000000002547dd9bf1e3ebe2c7cd052520855257d46f9ff8a775b61ae48af648")},
                {50000, uint256S("00000000e24d1dbb6826d506d78b4438662f23253a0aa01543ae4a2d8176dd1d")},

                {60000, uint256S("0000000080cc72f921cc3fb953c998403dc70cc83662d941f86b42cf8641278b")},
                {70000, uint256S("0000000039b8e6baf66cf149b7052d083646652eb391c1025763ab9015c74a53")},
                {80000, uint256S("00000000a41447620fb99b5bf7c0c247293b7bede20a61e377331643dce68f51")},
                {90000, uint256S("0000000099f41389242c91a98eb42268bef880a04260f18a370f7b6a4143daf3")}
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 0000000000000000000b9d2ec5a352ecba0592946514a92f14319dc2b367fc72
            /* nTime    */ 0, //1603995752,
            /* nTxCount */ 0, //582083445,
            /* dTxRate  */ 0, //3.508976121410527,
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = CBaseChainParams::TESTNET;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        //consensus.nSubsidyHalvingInterval = 210000;
        consensus.nSubsidyHalvingInterval = 500000;

        consensus.BIP16Exception = uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105");
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.CSVHeight = 770112; // 00000000025e930139bac5c6c31a403776da130831ab85be56578f3fa75369bb
        consensus.SegwitHeight = 834624; // 00000000002b980fcd729daaa248fd9316a5200e9b367f4ff2c42453e84201ca
        consensus.MinBIP9WarningHeight = 836640; // segwit activation height + miner confirmation window
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1619222400; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 1628640000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000001db6ec4ac88cf2272c6");
        consensus.defaultAssumeValid = uint256S("0x000000000000006433d1efec504c53ca332b64963c425395515b01977bd7b3b0"); // 1864000

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 40;
        m_assumed_chain_state_size = 2;

        //genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        
        genesis = CreateGenesisBlock(1742126400, 21640014, 0x1e0fffff, 1, 5000 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x000000a3e783409897a64245b1da6019da3696a75a67fc89b1398288ff6f6b3d"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4dd2ba10b788f92ed316aaf7465fedb2873a373b0378090c697a67d690a6f118"));

        /*
		python genesis.py  -z "BBC: 15/Mar/2025, US had productive talks with Putin over Ukraine war, Trump says." -n 20000000 -t 1742126400 -b 0x1e0fffff -v 500000000000
        04ffff001d01044c524242433a2031352f4d61722f323032352c205553206861642070726f647563746976652074616c6b73207769746820507574696e206f76657220556b7261696e65207761722c205472756d7020736179732e
        algorithm: SHA256
        merkle hash: 5694e0b86d592596c4443fa62badaf08e760fe06056503851a8985655105e4a5
        pszTimestamp: BBC: 15/Mar/2025, US had productive talks with Putin over Ukraine war, Trump says.
        pubkey: 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
        time: 1742126400
        bits: 0x1e0fffff
        Searching for genesis hash..
        204870.0 hash/s, estimate: 5.8 hgenesis hash found!
        nonce: 21640014
        genesis hash: 0000034a32d8621a713d4c538ddd3c1b0eb397c4eb06c226737de32aaddca609        
        */

        assert(consensus.hashGenesisBlock == uint256S("0000034a32d8621a713d4c538ddd3c1b0eb397c4eb06c226737de32aaddca609"));
        assert(genesis.hashMerkleRoot == uint256S("5694e0b86d592596c4443fa62badaf08e760fe06056503851a8985655105e4a5"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch");
        vSeeds.emplace_back("seed.tbtc.petertodd.org");
        vSeeds.emplace_back("seed.testnet.bitcoin.sprovoost.nl");
        vSeeds.emplace_back("testnet-seed.bluematt.me"); // Just a static list of stable node(s), only supports x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        //vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        m_is_test_chain = true;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                //{546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
                {0, uint256S("0000034a32d8621a713d4c538ddd3c1b0eb397c4eb06c226737de32aaddca609")},
             
            }
        };

        chainTxData = ChainTxData{
            // Data from RPC: getchaintxstats 4096 000000000000006433d1efec504c53ca332b64963c425395515b01977bd7b3b0
            /* nTime    */ 0, //1603359686,
            /* nTxCount */ 0, //58090238,
            /* dTxRate  */ 0, //0.1232886622799463,
        };
    }
};

/**
 * Signet
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const ArgsManager& args) {
        std::vector<uint8_t> bin;
        vSeeds.clear();

        if (!args.IsArgSet("-signetchallenge")) {
            bin = ParseHex("512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae");
            vSeeds.emplace_back("178.128.221.177");
            vSeeds.emplace_back("2a01:7c8:d005:390::5");
            vSeeds.emplace_back("v7ajjeirttkbnt32wpy3c6w3emwnfr3fkla7hpxcfokr3ysd3kqtzmqd.onion:38333");

            consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000000019fd16269a");
            consensus.defaultAssumeValid = uint256S("0x0000002a1de0f46379358c1fd09906f7ac59adf3712323ed90eb59e4c183c020"); // 9434
            m_assumed_blockchain_size = 1;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 0000002a1de0f46379358c1fd09906f7ac59adf3712323ed90eb59e4c183c020
                /* nTime    */ 0, //1603986000,
                /* nTxCount */ 0, //9582,
                /* dTxRate  */ 0, //0.00159272030651341,
            };
        } else {
            const auto signet_challenge = args.GetArgs("-signetchallenge");
            if (signet_challenge.size() != 1) {
                throw std::runtime_error(strprintf("%s: -signetchallenge cannot be multiple values.", __func__));
            }
            bin = ParseHex(signet_challenge[0]);

            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", signet_challenge[0]);
        }

        if (args.IsArgSet("-signetseednode")) {
            vSeeds = args.GetArgs("-signetseednode");
        }

        strNetworkID = CBaseChainParams::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        //consensus.nSubsidyHalvingInterval = 210000;
        consensus.nSubsidyHalvingInterval = 500000;
        consensus.BIP16Exception = uint256{};
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("00000377ae000000000000000000000000000000000000000000000000000000");
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        CHashWriter h(SER_DISK, 0);
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        memcpy(pchMessageStart, hash.begin(), 4);

        nDefaultPort = 38333;
        nPruneAfterHeight = 1000;

        //genesis = CreateGenesisBlock(1598918400, 52613770, 0x1e0377ae, 1, 50 * COIN);
        genesis = CreateGenesisBlock(1742126400, 30429951, 0x1e0fffff, 1, 5000 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x000000e116bba2400c14655a48604fea0da553e2272059d00c61c22ce01832c5"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4dd2ba10b788f92ed316aaf7465fedb2873a373b0378090c697a67d690a6f118"));

        /*
        python genesis.py  -z "BBC: 15/Mar/2025, US had productive talks with Putin over Ukraine war, Trump says." -n 30000000 -t 1742126400 -b 0x1e0fffff -v 500000000000
        04ffff001d01044c524242433a2031352f4d61722f323032352c205553206861642070726f647563746976652074616c6b73207769746820507574696e206f76657220556b7261696e65207761722c205472756d7020736179732e
        algorithm: SHA256
        merkle hash: 5694e0b86d592596c4443fa62badaf08e760fe06056503851a8985655105e4a5
        pszTimestamp: BBC: 15/Mar/2025, US had productive talks with Putin over Ukraine war, Trump says.
        pubkey: 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
        time: 1742126400
        bits: 0x1e0fffff
        Searching for genesis hash..
        genesis hash found!
        nonce: 30429951
        genesis hash: 00000d43e1b337527b3afcd97e3bb6e4797fbe3393f31ac6e2548d366824a179
        */

        assert(consensus.hashGenesisBlock == uint256S("00000d43e1b337527b3afcd97e3bb6e4797fbe3393f31ac6e2548d366824a179"));
        assert(genesis.hashMerkleRoot == uint256S("5694e0b86d592596c4443fa62badaf08e760fe06056503851a8985655105e4a5"));

        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID =  CBaseChainParams::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 500; // BIP34 activated on regtest (Used in functional tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in functional tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in functional tests)
        consensus.CSVHeight = 432; // CSV activated on regtest (Used in rpc activation tests)
        consensus.SegwitHeight = 0; // SEGWIT is always activated on regtest unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        UpdateActivationParametersFromArgs(args);

        //genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        //genesis = CreateGenesisBlock(1629450300, 25874086, 0x1e00ffff, 1, 50 * COIN);

        /*
        
		python genesis.py  -z "BBC: 15/Mar/2025, US had productive talks with Putin over Ukraine war, Trump says." -n 40000000 -t 1742126400 -b 0x1e0fffff -v 500000000000
        04ffff001d01044c524242433a2031352f4d61722f323032352c205553206861642070726f647563746976652074616c6b73207769746820507574696e206f76657220556b7261696e65207761722c205472756d7020736179732e
        algorithm: SHA256
        merkle hash: 5694e0b86d592596c4443fa62badaf08e760fe06056503851a8985655105e4a5
        pszTimestamp: BBC: 15/Mar/2025, US had productive talks with Putin over Ukraine war, Trump says.
        pubkey: 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
        time: 1742126400
        bits: 0x1e0fffff
        Searching for genesis hash..
        genesis hash found!
        nonce: 40029800
        genesis hash: 00000c8521ef8aeed65fc85eeacab258be0b4ab572a3be97744a352c32e3ae53        
        */

        genesis = CreateGenesisBlock(1742126400, 40029800, 0x1e0fffff, 1, 5000 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x0000001e3fd2391ef981ad5556149c9b31647f4af9db6ba5fae2328ea077c29a"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4dd2ba10b788f92ed316aaf7465fedb2873a373b0378090c697a67d690a6f118"));

        assert(consensus.hashGenesisBlock == uint256S("00000c8521ef8aeed65fc85eeacab258be0b4ab572a3be97744a352c32e3ae53"));
        assert(genesis.hashMerkleRoot == uint256S("5694e0b86d592596c4443fa62badaf08e760fe06056503851a8985655105e4a5"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = true;
        m_is_test_chain = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256S("00000c8521ef8aeed65fc85eeacab258be0b4ab572a3be97744a352c32e3ae53")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout, int min_activation_height)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
        consensus.vDeployments[d].min_activation_height = min_activation_height;
    }
    void UpdateActivationParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateActivationParametersFromArgs(const ArgsManager& args)
{
    if (args.IsArgSet("-segwitheight")) {
        int64_t height = args.GetArg("-segwitheight", consensus.SegwitHeight);
        if (height < -1 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Activation height %ld for segwit is out of valid range. Use -1 to disable segwit.", height));
        } else if (height == -1) {
            LogPrintf("Segwit disabled for testing\n");
            height = std::numeric_limits<int>::max();
        }
        consensus.SegwitHeight = static_cast<int>(height);
    }

    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() < 3 || 4 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]");
        }
        int64_t nStartTime, nTimeout;
        int min_activation_height = 0;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4 && !ParseInt32(vDeploymentParams[3], &min_activation_height)) {
            throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout, min_activation_height);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d\n", vDeploymentParams[0], nStartTime, nTimeout, min_activation_height);
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

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN) {
        return std::unique_ptr<CChainParams>(new CMainParams());
    } else if (chain == CBaseChainParams::TESTNET) {
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    } else if (chain == CBaseChainParams::SIGNET) {
        return std::unique_ptr<CChainParams>(new SigNetParams(args));
    } else if (chain == CBaseChainParams::REGTEST) {
        return std::unique_ptr<CChainParams>(new CRegTestParams(args));
    }
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(gArgs, network);
}
