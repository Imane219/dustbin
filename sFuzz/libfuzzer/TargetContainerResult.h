#pragma once
#include <vector>
#include <map>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  //目标执行结果
  struct TargetContainerResult {
    TargetContainerResult() {}
    TargetContainerResult(
        unordered_set<string> tracebits,
        unordered_map<string, u256> predicates,	
        unordered_set<string> uniqExceptions,	
        string cksum
    );

    /* Contains execution paths */
	//分支ID(jump-pc:jumpdest-pc)的集合
    unordered_set<string> tracebits;
    /* Save predicates */
    //hashmap: 分支ID-distance值
    unordered_map<string, u256> predicates;
    /* Exception path */
    //出现异常的pc的集合
    unordered_set<string> uniqExceptions;
    /* Contains checksum of tracebits */
	//合约所以的分支ID的字符串
    string cksum;
  };
}
