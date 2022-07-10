//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.3;
pragma abicoder v2; // required to accept structs as function parameters

import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import "@openzeppelin/contracts/utils/math/SafeMath.sol";

import "./DawnNFTStorage.sol";

// import "hardhat/console.sol";

contract DawnNFT is
    Initializable,
    UUPSUpgradeable,
    ERC721URIStorageUpgradeable,
    EIP712Upgradeable,
    AccessControlUpgradeable,
    OwnableUpgradeable,
    DawnNFTStorageV1
{
    using SafeMath for uint256;
    using SafeMath for uint256;

    uint256 constant VERSION = 0x1;

    bytes32 public constant DawnNFT_TYPEHASH =
        keccak256(
            "NFTVoucher(uint256 tokenId,uint256 minPrice,address creator,address publisher,uint256 ratio,string uri)"
        );

    event Redeem(
        address indexed creator,
        address indexed publisher,
        address indexed buyer,
        uint256 tokenId,
        uint256 price
    );

    // constructor(address payable minter)
    //   ERC721Upgradeable("DigitalPlanetNFT", "DPNFT")
    //   EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION) {
    //     _setupRole(MINTER_ROLE, minter);
    //     // _setRoleAdmin(MINTER_ROLE, msg.sender);
    //     // 部署者为管理员
    //     _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
    //     feeTo = msg.sender;
    // }

    function DawnNFT_init(address minter) private {
        _setupRole(MINTER_ROLE, minter);
        // _setRoleAdmin(MINTER_ROLE, msg.sender);
        // 部署者为管理员
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        feeTo = msg.sender;
        firstSaleFee = 1500;
        dawnNFTUri = "https://nft.dawz.xyz/";
    }

    function initialize() public payable initializer {
        __ERC721_init("DawnNFT", "DawnNFT");
        __ERC721URIStorage_init();
        __EIP712_init(SIGNING_DOMAIN, SIGNATURE_VERSION);
        __AccessControl_init();
        __Ownable_init();

        DawnNFT_init(msg.sender);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        view
        override
    {
        newImplementation;
        require(msg.sender == owner(), "no auth");
    }

    struct NFTVoucher {
        uint256 tokenId;
        uint256 minPrice;
        // bool verifyPrice;
        address creator; // 创作者
        address publisher; // 发行商
        uint256 ratio; // 发行商的分成比例, 分母为 10000
        string uri;
        bytes signature;
    }

    modifier validNFToken(uint256 _tokenId) {
        require(_exists(_tokenId), "nft not exists");
        _;
    }

    // 获取出版社-艺术家的版税分成
    function getPubishFeeRatio(address _pub, address _creator)
        public
        view
        returns (uint256)
    {
        uint256 ratio = publisherCreatorRatio[_pub][_creator];
        if (ratio > 0) {
            return ratio;
        }

        // 默认分成
        return publisherRatio[_pub];
    }

    // function printSelector() public view {
    //   console.log("this: %s", address(this));
    //   console.logBytes4(this.redeem.selector);
    //   console.logBytes4(this.verify.selector);
    //   console.logBytes4(this.withdraw.selector);
    // }

    /// @notice mint NFT token to msg.sender.
    /// @param tokenId The tokenId for mint.
    function mint(uint256 tokenId) public onlyOwner {
      _mint(_msgSender(), tokenId);
    }

    function mintMany(address to, uint from, uint end) external onlyOwner {
      for (uint i = from; i < end; i++) {
        _mint(to, i);
      }
    }

    /// @notice burn NFT token.
    /// @param tokenId The tokenId for mint.
    function burn(uint256 tokenId) public {
        require (ownerOf(tokenId) == msg.sender, "no auth");
        _burn(tokenId);
    }

    /// @notice burnMany burn NFT token.
    /// @param start The tokenId for mint.
    /// @param end The tokenId for mint.
    function burnMany(uint256 start, uint256 end) public {
      for (uint i = start; i < end; i++) {
        require (ownerOf(i) == msg.sender, "no auth");
        _burn(i);
      }
    }

    function _baseURI() internal view override returns (string memory) {
        return dawnNFTUri;
    }

    function setBaseURI(string calldata uri) external onlyOwner {
        dawnNFTUri = uri;
    }

    /// @notice Transfers all pending withdrawal balance to the caller. Reverts if the caller is not an authorized minter.
    function withdraw() public {
        require(
            hasRole(MINTER_ROLE, _msgSender()),
            "Only authorized minters can withdraw"
        );

        // IMPORTANT: casting _msgSender() to a payable address is only safe if ALL members of the minter role are payable addresses.
        address payable receiver = payable(_msgSender());

        uint256 amount = pendingWithdrawals[receiver];
        // zero account before transfer to prevent re-entrancy attack
        pendingWithdrawals[receiver] = 0;
        receiver.transfer(amount);
    }

    /// @notice Retuns the amount of Ether available to the caller to withdraw.
    function availableToWithdraw() public view returns (uint256) {
        return pendingWithdrawals[_msgSender()];
    }

    /// @notice Returns a hash of the given NFTVoucher, prepared using EIP712 typed data hashing rules.
    /// @param voucher An NFTVoucher to hash.
    function _hash(NFTVoucher memory voucher) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256(
                            "NFTVoucher(uint256 tokenId,uint256 minPrice,address creator,address publisher,uint256 ratio,string uri)"
                        ),
                        voucher.tokenId,
                        voucher.minPrice,
                        voucher.creator,
                        voucher.publisher,
                        voucher.ratio,
                        keccak256(bytes(voucher.uri))
                    )
                )
            );
    }

    /// @notice Returns a hash of the given NFTVoucher, prepared using EIP712 typed data hashing rules.
    /// @param tokenId tokenId.
    /// @param minPrice nft min price.
    /// @param creator the creator.
    /// @param uri uri.
    function getDigest(
        uint256 tokenId,
        uint256 minPrice,
        address creator,
        address publisher,
        uint256 ratio,
        string memory uri
    ) public view returns (bytes32 digest) {
        NFTVoucher memory voucher;
        voucher.tokenId = tokenId;
        voucher.minPrice = minPrice;
        voucher.creator = creator;
        voucher.publisher = publisher;
        voucher.ratio = ratio;
        voucher.uri = uri;

        digest = _hash(voucher);
        // digest = _hashTypedDataV4(keccak256(abi.encode(
        //   keccak256("NFTVoucher(uint256 tokenId,uint256 minPrice,string uri)"),
        //   tokenId,
        //   minPrice,
        //   creator,
        //   keccak256(bytes(uri))
        // )));
    }

    /// @notice Returns the chain id of the current blockchain.
    /// @dev This is used to workaround an issue with ganache returning different values from the on-chain chainid() function and
    ///  the eth_chainId RPC method. See https://github.com/protocol/nft-website/issues/121 for context.
    function getChainID() external view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /// @notice Verifies the signature for a given NFTVoucher, returning the address of the signer.
    /// @dev Will revert if the signature is invalid. Does not verify that the signer is authorized to mint NFTs.
    /// @param voucher An NFTVoucher describing an unminted NFT.
    function _verify(NFTVoucher calldata voucher)
        internal
        view
        returns (address)
    {
        bytes32 digest = _hash(voucher);
        return ECDSAUpgradeable.recover(digest, voucher.signature);
    }

    function verify(NFTVoucher calldata voucher)
        external
        view
        returns (address)
    {
        return _verify(voucher);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlUpgradeable, ERC721Upgradeable)
        returns (bool)
    {
        return
            ERC721Upgradeable.supportsInterface(interfaceId) ||
            AccessControlUpgradeable.supportsInterface(interfaceId);
    }

    function _setTokenAttributes(
        uint256 _tokenId,
        uint8 _typeAttributes,
        string memory _tvalue,
        uint256 _tUintValue
    ) internal validNFToken(_tokenId) {
        if (_typeAttributes == 1) {
            attributesOf[_tokenId].atterbutes1 = _tvalue;
        } else if (_typeAttributes == 2) {
            attributesOf[_tokenId].atterbutes2 = _tvalue;
        } else if (_typeAttributes == 3) {
            attributesOf[_tokenId].atterbutes3 = _tUintValue;
        } else if (_typeAttributes == 4) {
            attributesOf[_tokenId].atterbutes4 = _tUintValue;
        } else if (_typeAttributes == 5) {
            attributesOf[_tokenId].atterbutes5 = _tUintValue;
        } else if (_typeAttributes == 6) {
            attributesOf[_tokenId].atterbutes6 = _tUintValue;
        }
    }

    function _setToken7Attributes(
        uint256 _tokenId,
        uint256 _index,
        uint256 _tvalue
    ) internal validNFToken(_tokenId) {
        attributesOf[_tokenId].atterbutes7[_index] = _tvalue;
    }

    // 设置出版社分成比例
    function _setNFTPublisherRatio(uint256 _tokenId, uint256 _ratio)
        internal
        validNFToken(_tokenId)
    {
        NFTCreator storage item = nftCreators[_tokenId];
        item.ratio = _ratio;
    }

    function _addToken7Attributes(uint256 _tokenId, uint256 _tvalue)
        internal
        validNFToken(_tokenId)
    {
        attributesOf[_tokenId].atterbutes7.push(_tvalue);
    }

    function getAttributes7Length(uint256 _tokenId)
        public
        view
        returns (uint256)
    {
        return attributesOf[_tokenId].atterbutes7.length;
    }

    function getAttributes7ValuebyIndex(uint256 _tokenId, uint256 _index)
        public
        view
        returns (uint256)
    {
        return attributesOf[_tokenId].atterbutes7[_index];
    }

    // 设置已经 mint 的商品的版税分成
    function setNFTPublisherRatio(uint256 _tokenId, uint256 _ratio)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        _setNFTPublisherRatio(_tokenId, _ratio);
    }

    function setTokenAttributes(
        uint256 _tokenId,
        uint8 _typeAttributes,
        string calldata _tvalue,
        uint256 _tUintValue
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setTokenAttributes(_tokenId, _typeAttributes, _tvalue, _tUintValue);
    }

    function setAttribute7(
        uint256 _tokenId,
        uint256 _index,
        uint256 _tvalue
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setToken7Attributes(_tokenId, _index, _tvalue);
    }

    function addToken7Attributes(uint256 _tokenId, uint256 _tvalue)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        _addToken7Attributes(_tokenId, _tvalue);
    }

    function setFirstSaleFee(uint256 fee)
        external
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        require(fee < DENOMINATOR, "fee too high");
        firstSaleFee = fee;
    }

    function setPublishRatio(uint256 _ratio) external onlyRole(PUBLISHER_ROLE) {
        publisherRatio[_msgSender()] = _ratio;
    }
}
