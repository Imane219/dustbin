pragma solidity ^0.4.8;
contract SimpleDAO {
    mapping(address => uint) public credit;

    function donate(address to) payable public {
        credit[to] += msg.value;
    }
    // INSECURE
    function withdraw(uint amount) public {
        if (credit[msg.sender] >= amount) {
            // Send ethereum to msg.sender
            require(msg.sender.call.value(amount)());
            // Deduce the balance of msg.sender
            credit[msg.sender] -= amount;
        }
    }

    function queryCredit(address to) view public returns(uint) {
        return credit[to];
    }
}
