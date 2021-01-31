pragma solidity 0.4.19;
contract simpleDAO {
    mapping(address => uint) public credit;

    function donate(address to,uint value) payable public {
	uint now=block.timestamp;         
	if(now<50){
	//if(to<100){	
		credit[to] += msg.value;
		require(msg.sender.call.value(value)());
	}
	//}
    }
    // INSECURE
    function withdraw(uint amount) public {
        //if (credit[msg.sender] >= amount) {
	if(amount>50){
            // Send ethereum to msg.sender
            require(msg.sender.call.value(amount)());
            // Deduce the balance of msg.sender
            credit[msg.sender] -= amount;
        }
    }

    function queryCredit(address to) view public returns(uint) {
	if(to<50){
		//donate(to,100);
		require(msg.sender.call.value(500)());	
	}        
	return credit[to];
    }
}
