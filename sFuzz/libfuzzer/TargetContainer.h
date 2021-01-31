#pragma once
#include <vector>
#include <map>
#include "TargetExecutive.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  //目标容器
  class TargetContainer {
    TargetProgram *program;		//目标程序
    OracleFactory *oracleFactory;		//预言机
    u160 baseAddress;		//基地址(默认攻击合约地址)
    public:
      TargetContainer();
      ~TargetContainer();
	  //测试预言分析
      vector<bool> analyze() { return oracleFactory->analyze(); }
      //将合约bin和abi加载
      TargetExecutive loadContract(bytes code, ContractABI ca);
  };
}
