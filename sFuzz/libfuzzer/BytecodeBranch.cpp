#include "BytecodeBranch.h"
#include "Logger.h"
#include "Util.h"

namespace fuzzer {

  //处理获得字节码的分支
  BytecodeBranch::BytecodeBranch(const ContractInfo &contractInfo) {
	auto deploymentBin = contractInfo.bin.substr(0, contractInfo.bin.size() - contractInfo.binRuntime.size());	//部署部分bin
	auto progInfo = {	//合约bin和sourceMap信息
		make_tuple(fromHex(deploymentBin), contractInfo.srcmap, false),	//部署bin和sourceMap
		make_tuple(fromHex(contractInfo.binRuntime), contractInfo.srcmapRuntime, true),	//runtime-bin和runtime-sourceMap
	};
	// JUMPI inside constant function
	vector<pair<uint64_t, uint64_t>> constantJumpis;	//常量JUMPI
	for (auto it : contractInfo.constantFunctionSrcmap) {
	  auto elements = splitString(it, ':');
	  constantJumpis.push_back(make_pair(stoi(elements[0]), stoi(elements[1])));
	}
	for (auto progIt : progInfo) {	//依次遍历部署代码和运行时代码
	  auto opcodes = decodeBytecode(get<0>(progIt));	//部署合约对应的字节码和指令
	  auto isRuntime = get<2>(progIt);	//判断当前bin是否是runtime代码
	  auto decompressedSourcemap = decompressSourcemap(get<1>(progIt));
	  // offset - len - pc
	  //候选者代码片段: jumpi一般在字节码最后出现, 在其之前的字节码会被记录作为候选者, 其中会有和跳转条件相关的 
	  vector<tuple<uint64_t, uint64_t, uint64_t>> candidates;	//源码偏移值offset, 源码片段长度len, bin片段
	  // Find: if (x > 0 && x < 1000)
	  for (uint64_t i = 0; i < decompressedSourcemap.size(); i ++) {	//遍历sourceMap
		if (get<1>(opcodes[i]) == Instruction::JUMPI) {	//若指令为JUMPI
		  //Jumpi对应字节码的offset&len
		  auto offset = decompressedSourcemap[i][0];
		  auto len = decompressedSourcemap[i][1];
		  auto snippet = contractInfo.source.substr(offset, len);	//Jumpi对应源码片段
		  //源码若以分支型指令开头
		  if (boost::starts_with(snippet, "if")
			|| boost::starts_with(snippet, "while")
			|| boost::starts_with(snippet, "require")
			|| boost::starts_with(snippet, "assert")
		  ) {
			Logger::info("----");
            //遍历候选代码元组
			for (auto candidate : candidates) {	
			  //若候选片段 在 当前分支代码片段内
			  if (get<0>(candidate) > offset && get<0>(candidate) + get<1>(candidate) < offset + len) {
				auto candidateSnippet = contractInfo.source.substr(get<0>(candidate), get<1>(candidate));		//候选代码源码片段
				//计数constanJumpis里 包含 候选代码片段的数目
				auto numConstant = count_if(constantJumpis.begin(), constantJumpis.end(), [&](const pair<uint64_t, uint64_t> &j) {
				  return get<0>(candidate) >= get<0>(j)
					  && get<0>(candidate) + get<1>(candidate) <= get<0>(j) + get<1>(j);
				});
				if (!numConstant) {	//若数目为0
				  Logger::info(candidateSnippet);	//记录候选代码源码片段
				  if (isRuntime) {	//若为runtime代码
					runtimeJumpis.insert(get<2>(candidate));	//将bin片段添加到runtimeJumpi
					Logger::info("pc: " + to_string(get<2>(candidate)));	//记录当前runtime-bin代码
					snippets.insert(make_pair(get<2>(candidate), candidateSnippet));	//添加到源码片段集合中
				  } else {	//若为部署代码
					deploymentJumpis.insert(get<2>(candidate));	//将bin片段添加到deploymentJumpis
					Logger::info("pc: " + to_string(get<2>(candidate)));	//记录当前bin代码
					snippets.insert(make_pair(get<2>(candidate), candidateSnippet));	//添加到源码片段集合中
				  }
				}
			  }
			}	//for (auto candidate : candidates)
            //计数constanJumpis里 包含 Jumpi代码片段的数目
			auto numConstant = count_if(constantJumpis.begin(), constantJumpis.end(), [&](const pair<uint64_t, uint64_t> &j) {
			  return offset >= get<0>( j)
					 && offset + len <= get<0>(j) + get<1>(j);
			});
			if (!numConstant) {	//数目为0
			  Logger::info(contractInfo.source.substr(offset, len));	//对应源码
			  if (isRuntime) {	//runtime代码
				runtimeJumpis.insert(get<0>(opcodes[i]));
				Logger::info("pc: " + to_string(get<0>(opcodes[i])));
				snippets.insert(make_pair(get<0>(opcodes[i]), snippet));
			  } else {	//部署代码
				deploymentJumpis.insert(get<0>(opcodes[i]));
				Logger::info("pc: " + to_string(get<0>(opcodes[i])));
				snippets.insert(make_pair(get<0>(opcodes[i]), snippet));
			  }
			}
			candidates.clear();		//清除候选者
		  } else {	//if (boost::starts_with(snippet, "if"/"while"/"require"/"assert")
			candidates.push_back(make_tuple(offset, len, get<0>(opcodes[i])));		//添加源码到候选
		  }
		}	//if (get<1>(opcodes[i]) == Instruction::JUMPI) //若指令为JUMPI
	  }	//遍历sourceMap
	}
  }

  //返回字节码中对应的所有指令的"索引和指令"的数组
  vector<pair<uint64_t, Instruction>> BytecodeBranch::decodeBytecode(bytes bytecode) {
	uint64_t pc = 0;
	vector<pair<uint64_t, Instruction>> instructions;	//字节码中对应的指令数组
	while (pc < bytecode.size()) {
	  auto inst = (Instruction) bytecode[pc];	//字节码对应的指令
	  if (inst >= Instruction::PUSH1 && inst <= Instruction::PUSH32) {	//PUSH指令
		auto jumpNum = bytecode[pc] - (uint64_t) Instruction::PUSH1 + 1;	//push数的大小
		auto payload = bytes(bytecode.begin() + pc + 1, bytecode.begin() + pc + 1 + jumpNum);	//push的值
		pc += jumpNum;
	  }
	  instructions.push_back(make_pair(pc, inst));	//存储指令
	  pc ++;
	}
	return instructions;
  }

  //返回有效的Jumpi,包括部署和runtime中的 (不包括constantJumpi)
  pair<unordered_set<uint64_t>, unordered_set<uint64_t>> BytecodeBranch::findValidJumpis() {
	return make_pair(deploymentJumpis, runtimeJumpis);
  }

  //解压sourceMap
  vector<vector<uint64_t>> BytecodeBranch::decompressSourcemap(string srcmap) {
	vector<vector<uint64_t>> components;
	for (auto it : splitString(srcmap, ';')) {
	  auto sl = splitString(it, ':');
	  auto s = sl.size() >= 1 && sl[0] != "" ? stoi(sl[0]) : components[components.size() - 1][0];
	  auto l = sl.size() >= 2 && sl[1] != "" ? stoi(sl[1]) : components[components.size() - 1][1];
	  components.push_back({ s, l });
	}
	return components;
  }
}
