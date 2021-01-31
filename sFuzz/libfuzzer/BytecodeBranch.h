#pragma once

#include "Common.h"
#include "Util.h"
#include "Fuzzer.h"

namespace fuzzer {

  class BytecodeBranch {
    private:
	  //部署代码Jumpi的bin
      unordered_set<uint64_t> deploymentJumpis;
	  //运行时代码Jumpi的bin
	  unordered_set<uint64_t> runtimeJumpis;
    public:
      //有效Jumpi的字节码&源码片段
      unordered_map<uint64_t, string> snippets;
      //处理获得字节码的分支
      BytecodeBranch(const ContractInfo &contractInfo);
      //返回有效的Jumpi,包括部署和runtime中的 (不包括constantJumpi)
      pair<unordered_set<uint64_t>, unordered_set<uint64_t>> findValidJumpis();
      static vector<vector<uint64_t>> decompressSourcemap(string srcmap);
      static vector<pair<uint64_t, Instruction>> decodeBytecode(bytes bytecode);
  };

}
