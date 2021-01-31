#pragma once
#include <vector>
#include <map>
#include <liboracle/OracleFactory.h>
#include "Common.h"
#include "TargetProgram.h"
#include "ContractABI.h"
#include "TargetContainerResult.h"
#include "Util.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  //记录的参数
  struct RecordParam {
    u64 lastpc = 0;
    bool isDeployment = false;	//记录合约是部署代码还是运行时代码
  };
  //目标执行程序
  class TargetExecutive {
      TargetProgram *program;
      OracleFactory *oracleFactory;
      ContractABI ca;
      bytes code;
    public:
      Address addr;		//合约地址(第一个实例是攻击合约地址,后面是待测合约地址)
      //目标执行程序
      TargetExecutive(OracleFactory *oracleFactory, TargetProgram *program, Address addr, ContractABI ca, bytes code) {
        this->code = code;
        this->ca = ca;
        this->addr = addr;
        this->program = program;
        this->oracleFactory = oracleFactory;
      }
	  //执行合约
      TargetContainerResult exec(bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      void deploy(bytes data, OnOpFunc onOp);
  };
}
