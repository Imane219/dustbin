#pragma once
#include <vector>
#include "LastBlockHashes.h"
#include "ContractABI.h"


using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum ContractCall { CONTRACT_CONSTRUCTOR, CONTRACT_FUNCTION };
  class TargetProgram {
    private:
      State state;
      u256 gas;
      int64_t timestamp;
      int64_t blockNumber;
      u160 sender;
      EnvInfo *envInfo;
      SealEngineFace *se;
      ExecutionResult invoke(Address addr, bytes data, bool payable, OnOpFunc onOp);
    public:
      TargetProgram();
      ~TargetProgram();
      //获取账户余额
      u256 getBalance(Address addr);
      bytes getCode(Address addr);
      map<h256, pair<u256, u256>> storage(Address const& addr);
	  //设置账户余额
      void setBalance(Address addr, u256 balance);
      //部署code到账户地址
      void deploy(Address addr, bytes code);
	  //更新环境
      void updateEnv(Accounts accounts, FakeBlock block);
      unordered_map<Address, u256> addresses();
      //在状态更改日志中创建一个保存点
      size_t savepoint();
	  //回滚到保存点
      void rollback(size_t savepoint);
	  //调用合约函数
      ExecutionResult invoke(Address addr, ContractCall type, bytes data, bool payable, OnOpFunc onOp);
  };
}
