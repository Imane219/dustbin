#include "TargetProgram.h"
#include "Util.h"

using namespace dev;
using namespace eth;

namespace fuzzer {
  TargetProgram::TargetProgram(): state(State(0)) {
    Network networkName = Network::MainNetworkTest;
    LastBlockHashes lastBlockHashes;
    BlockHeader blockHeader;
    s64 maxGasLimit = ChainParams(genesisInfo(networkName))
      .maxGasLimit.convert_to<s64>();
    gas = MAX_GAS;
    timestamp = 0;
    blockNumber = 2675000;
    Ethash::init();
    NoProof::init();
    se = ChainParams(genesisInfo(networkName)).createSealEngine();
    // add value
    blockHeader.setGasLimit(maxGasLimit);
    blockHeader.setTimestamp(timestamp);
    blockHeader.setNumber(blockNumber);
    envInfo = new EnvInfo(blockHeader, lastBlockHashes, 0);
  }
  
  void TargetProgram::setBalance(Address addr, u256 balance) {
    state.setBalance(addr, balance);
  }

  //获取账户余额
  u256 TargetProgram::getBalance(Address addr) {
    return state.balance(addr);
  }

  //部署code到账户地址
  void TargetProgram::deploy(Address addr, bytes code) {	//code为字节码
    state.clearStorage(addr);	//将帐户的存储根哈希清除为空trie的哈希。
    state.setCode(addr, bytes{code});	//设置帐户代码, 必须仅在合同创建期间/之后调用。
  }
    
  bytes TargetProgram::getCode(Address addr) {
    return state.code(addr);
  }

  //调用合约函数
  ExecutionResult TargetProgram::invoke(Address addr, ContractCall type, bytes data, bool payable, OnOpFunc onOp) {
	//data为编码后的参数数据
    switch (type) {
      case CONTRACT_CONSTRUCTOR: {	//合约构造函数
        bytes code = state.code(addr);
        code.insert(code.end(), data.begin(), data.end());	//添加编码的数据
        state.setCode(addr, bytes{code});
        ExecutionResult res = invoke(addr, data, payable, onOp);
        state.setCode(addr, bytes{res.output});
        return res;
      }
      case CONTRACT_FUNCTION: {		//合约函数
        return invoke(addr, data, payable, onOp);
      }
      default: {
        throw "Unknown invoke type";
      }
    }
  }

  //调用
  ExecutionResult TargetProgram::invoke(Address addr, bytes data, bool payable, OnOpFunc onOp) {
    ExecutionResult res;
    Address senderAddr(sender);
    u256 value = payable ? state.balance(sender) / 2 : 0;	//交易金额是余额的一半
    u256 gasPrice = 0;
    Transaction t = Transaction(value, gasPrice, gas, data, state.getNonce(sender));
    t.forceSender(senderAddr);
    Executive executive(state, *envInfo, *se);
    executive.setResultRecipient(res);
    executive.initialize(t);
    LegacyVM::payload = data;
    executive.call(addr, senderAddr, value, gasPrice, &data, gas);
    executive.updateBlock(blockNumber, timestamp);	//更新区块号和时间戳
    executive.go(onOp);
    executive.finalize();
    return res;
  }


  void TargetProgram::updateEnv(Accounts accounts, FakeBlock block) {
    for (auto account: accounts) {	//遍历所有账户
      auto address = get<1>(account);
      auto balance = get<2>(account);
      auto isSender = get<3>(account);
      state.setBalance(Address(address), balance);	//设置账户余额
      if (isSender) sender = address;
    }
    blockNumber = get<1>(block);
    timestamp = get<2>(block);
  }

  //回滚到保存点
  void TargetProgram::rollback(size_t savepoint) {
    state.rollback(savepoint);
  }

  //在状态更改日志中创建一个保存点
  size_t TargetProgram::savepoint() {
    return state.savepoint();
  }
  
  TargetProgram::~TargetProgram() {
    delete envInfo;
    delete se;
  }
}

