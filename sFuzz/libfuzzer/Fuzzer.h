#pragma once
#include <iostream>
#include <vector>
#include <liboracle/Common.h>
#include "ContractABI.h"
#include "Util.h"
#include "FuzzItem.h"
#include "Mutation.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum FuzzMode { AFL };
  enum Reporter { TERMINAL, JSON, BOTH };
  //合约信息
  struct ContractInfo {
    string abiJson;
    string bin;
    string binRuntime;
    string contractName;
    string srcmap;
    string srcmapRuntime;
    string source;
    vector<string> constantFunctionSrcmap;	//constant函数源码
    bool isMain;	//是否是测试合约
  };
  //模糊测试参数
  struct FuzzParam {
    vector<ContractInfo> contractInfo;	//合约信息
    FuzzMode mode;	//测试模式
    Reporter reporter;	//报告形式:终端/json文件
    int duration;	//时长
    int analyzingInterval;	//测试间隔
    string attackerName;	//攻击合约名
  };
  //模糊测试状态
  struct FuzzStat {
    int idx = 0;
    uint64_t maxdepth = 0;		//最大深度
    bool clearScreen = false;	//清屏标识
    int totalExecs = 0;		//合约总执行次数
    int queueCycle = 0;		//循环测试轮数
    int stageFinds[32];
    double lastNewPath = 0;
  };

  //模糊测试项目+distance
  struct Leader {
    FuzzItem item;	//模糊测试项目
    u256 comparisonValue = 0;	//distance
    Leader(FuzzItem _item, u256 _comparisionValue): item(_item) {
      comparisonValue = _comparisionValue;
    }
  };

  class Fuzzer {
    vector<bool> vulnerabilities;
    vector<string> queues;	//已发现的分支ID
    unordered_set<string> tracebits;	//已覆盖分支集合
    unordered_set<string> predicates;	//分支ID和distance集合
    unordered_map<string, Leader> leaders;	//发现的(可能未覆盖)分支集:<分支ID,leader{测试项目,distance}>, 可视为离散的CFG结点
    unordered_map<uint64_t, string> snippets;	//代码片段: 代码bin+对应源码
    unordered_set<string> uniqExceptions;	//异常
    Timer timer;	//计时器
    FuzzParam fuzzParam;	//模糊测试参数
    FuzzStat fuzzStat;		//模糊测试状态
    void writeStats(const Mutation &mutation);
    ContractInfo mainContract();
    public:
      Fuzzer(FuzzParam fuzzParam);
      FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      void showStats(const Mutation &mutation, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      void updateTracebits(unordered_set<string> tracebits);
      void updatePredicates(unordered_map<string, u256> predicates);
      void updateExceptions(unordered_set<string> uniqExceptions);
      void start();
      void stop();
  };
}
