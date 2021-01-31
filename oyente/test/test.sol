pragma solidity ^0.4.19;

contract test {

    mapping(address => uint) public credit;


    function withdraw(uint amount,uint[2] sss,uint[2] ttt) public {

	if(sss[0]>10){        
              	require(msg.sender.call.value(amount)());
            	credit[msg.sender] -= amount;
        }
     }

}
