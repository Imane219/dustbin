#pragma once
#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

//测试预言工厂
class OracleFactory {
    MultipleFunction functions;
    SingleFunction function;
    vector<bool> vulnerabilities;	//漏洞标识
  public:
	//预言工厂初始化
    void initialize();
    //预言工厂结束
    void finalize();
	//存储opcode语境
    void save(OpcodeContext ctx);
    vector<bool> analyze();
};
