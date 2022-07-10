//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.3;
pragma abicoder v2; // required to accept structs as function parameters

contract DawnNFTStorageV1 {
  bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
  bytes32 public constant PUBLISHER_ROLE = keccak256("PUBLISHER_ROLE");
  string internal constant SIGNING_DOMAIN = "DawnNFT-Voucher";
  string internal constant SIGNATURE_VERSION = "1";

  struct NFTAttributes {
      string  atterbutes1;
      string  atterbutes2; 
      uint256 atterbutes3; // this for cid
      uint256 atterbutes4;
      uint256 atterbutes5;
      uint256 atterbutes6;
      uint256[] atterbutes7;
      // address migrateFrom;    // 从哪个合约转过来
      // uint256 originTokenId;  // 原来的tokenId
      // uint256 originChainId;  // 原来的chainId
  }

  struct NFTCreator {
    address creator;
    address pulisher;  // 发行商
    uint256 ratio;
  }

  // 分母均为 10000
  uint public constant DENOMINATOR = 10000;
  uint public firstSaleFee; // 首次销售手续费

  string dawnNFTUri;

  // 平台收益地址
  address public feeTo;
  mapping (uint256 => bool) public status;

  mapping (address => uint256) public pendingWithdrawals;
  mapping (uint256 => uint256) public nftSales;    // 卖出次数
  mapping (uint256 => NFTCreator) public nftCreators; // 创作者
  mapping(uint256 => NFTAttributes) public attributesOf;
  mapping(address => uint256) public publisherRatio;   // 出版社默认版税分成
  mapping(address => mapping(address => uint256)) public publisherCreatorRatio;   // 出版社-艺术家版税分成
}
