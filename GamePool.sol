// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract GamePool is Ownable {
    using SafeERC20 for IERC20;

    event Claim(address indexed user, uint256 uid, uint256 amount, uint256 nonce);
    event Pay(address indexed user, uint256 uid, uint256 amount);

    bytes32 constant CLAIM_ACTION_HASH = keccak256("claim");
    IERC20 constant NATIVE_TOKEN = IERC20(0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE);

    address public adminSigner;
    address public immutable token;

    mapping(uint256 => mapping(uint256 => bool)) public userClaimNonceUsed;

    constructor(address owner_, address adminSigner_, address token_) Ownable(owner_) {
        adminSigner = adminSigner_;
        token = token_;
    }

    function pay(uint256 amount, uint256 uid) external {
        address user = msg.sender;
        IERC20(token).safeTransferFrom(user, address(this), amount);
        emit Pay(user, uid, amount);
    }

    function pay(uint256 uid) external payable {
        emit Pay(msg.sender, uid, msg.value);
    }

    function claim(uint256 amount, uint256 uid, uint256 nonce, bytes calldata signature) external {
        address user = msg.sender;
        require(amount > 0, "zero amount");
        require(_checkSignature(CLAIM_ACTION_HASH, user, uid, amount, nonce, signature), "invalid signature");
        require(!userClaimNonceUsed[uid][nonce], "nonce already used");

        userClaimNonceUsed[uid][nonce] = true;

        _safeTransferOut(IERC20(token), user, amount);

        emit Claim(user, uid, amount, nonce);
    }

    function setAdminSigner(address adminSigner_) external onlyOwner {
        require(adminSigner_ != address(0), "zero address");
        adminSigner = adminSigner_;
    }

    function accidentWithdrawToken(IERC20 token_, uint256 amount) external onlyOwner {
        _safeTransferOut(token_, owner(), amount);
    }

    function _checkSignature(
        bytes32 signType,
        address user,
        uint256 uid,
        uint256 amount,
        uint256 nonce,
        bytes memory signature
    ) private view returns (bool) {
        bytes32 messageHash = MessageHashUtils.toEthSignedMessageHash(
            keccak256(abi.encodePacked(signType, user, uid, amount, nonce))
        );
        return ECDSA.recover(messageHash, signature) == adminSigner;
    }

    function _safeTransferOut(IERC20 token_, address to, uint256 amount) private {
        require(amount > 0, "zero transfer amount");
        if (token_ == NATIVE_TOKEN) {
            (bool success, ) = payable(to).call{value: amount}("");
            require(success, "native transfer failed");
        } else {
            token_.safeTransfer(to, amount);
        }
    }
}
