#include <fstream>
#include "Fuzzer.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"
#include "Logger.h"
#include "BytecodeBranch.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;
namespace pt = boost::property_tree;

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(FuzzParam fuzzParam): fuzzParam(fuzzParam){
  fill_n(fuzzStat.stageFinds, 32, 0);
}

/* Detect new exception */
//更新异常
void Fuzzer::updateExceptions(unordered_set<string> exps) {
  for (auto it: exps) uniqExceptions.insert(it);
}

/* Detect new bits by comparing tracebits to virginbits */
//更新分支ID集
void Fuzzer::updateTracebits(unordered_set<string> _tracebits) {
  for (auto it: _tracebits) tracebits.insert(it);
}

//更新记录的distance值
void Fuzzer::updatePredicates(unordered_map<string, u256> _pred) {
  for (auto it : _pred) {
    predicates.insert(it.first);
  };
  // Remove covered predicates
  //移除覆盖到的分支的distance值
  for(auto it = predicates.begin(); it != predicates.end(); ) {
    if (tracebits.count(*it)) {
      it = predicates.erase(it);
    } else {
      ++it;
    }
  }
}

//返回合约信息
ContractInfo Fuzzer::mainContract() {
  auto contractInfo = fuzzParam.contractInfo;
  auto first = contractInfo.begin();
  auto last = contractInfo.end();
  auto predicate = [](const ContractInfo& c) { return c.isMain; };
  auto it = find_if(first, last, predicate);
  return *it;
}

void Fuzzer::showStats(const Mutation &mutation, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis) {
  int numLines = 24, i = 0;
  if (!fuzzStat.clearScreen) {	//清屏
    for (i = 0; i < numLines; i++) cout << endl;
    fuzzStat.clearScreen = true;
  }
  //推移时间
  double duration = timer.elapsed();
  //距上次时间
  double fromLastNewPath = timer.elapsed() - fuzzStat.lastNewPath;
  for (i = 0; i < numLines; i++) cout << "\x1b[A";
  //变异的名称
  auto nowTrying = padStr(mutation.stageName, 20);	
  auto stageExecProgress = to_string(mutation.stageCur) + "/" + to_string(mutation.stageMax);
  auto stageExecPercentage = mutation.stageMax == 0 ? to_string(100) : to_string((uint64_t)((float) (mutation.stageCur) / mutation.stageMax * 100));
  auto stageExec = padStr(stageExecProgress + " (" + stageExecPercentage + "%)", 20);
  //执行数
  auto allExecs = padStr(to_string(fuzzStat.totalExecs), 20);
  //执行速度
  auto execSpeed = padStr(to_string((int)(fuzzStat.totalExecs / duration)), 20);	
  //循环百分比
  auto cyclePercentage = (uint64_t)((float)(fuzzStat.idx + 1) / leaders.size() * 100);
  //循环索引/百分比
  auto cycleProgress = padStr(to_string(fuzzStat.idx + 1) + " (" + to_string(cyclePercentage) + "%)", 20);
  auto cycleDone = padStr(to_string(fuzzStat.queueCycle), 15);
  //分支总数
  auto totalBranches = (get<0>(validJumpis).size() + get<1>(validJumpis).size()) * 2;
  auto numBranches = padStr(to_string(totalBranches), 15);
  //覆盖率=已覆盖分支数/总分支数
  auto coverage = padStr(to_string((uint64_t)((float) tracebits.size() / (float) totalBranches * 100)) + "%", 15);
  auto flip1 = to_string(fuzzStat.stageFinds[STAGE_FLIP1]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP1]);
  auto flip2 = to_string(fuzzStat.stageFinds[STAGE_FLIP2]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP2]);
  auto flip4 = to_string(fuzzStat.stageFinds[STAGE_FLIP4]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP4]);
  auto bitflip = padStr(flip1 + ", " + flip2 + ", " + flip4, 30);
  auto byte1 = to_string(fuzzStat.stageFinds[STAGE_FLIP8]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP8]);
  auto byte2 = to_string(fuzzStat.stageFinds[STAGE_FLIP16]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP16]);
  auto byte4 = to_string(fuzzStat.stageFinds[STAGE_FLIP32]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP32]);
  auto byteflip = padStr(byte1 + ", " + byte2 + ", " + byte4, 30);
  auto arith1 = to_string(fuzzStat.stageFinds[STAGE_ARITH8]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH8]);
  auto arith2 = to_string(fuzzStat.stageFinds[STAGE_ARITH16]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH16]);
  auto arith4 = to_string(fuzzStat.stageFinds[STAGE_ARITH32]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH32]);
  auto arithmetic = padStr(arith1 + ", " + arith2 + ", " + arith4, 30);
  auto int1 = to_string(fuzzStat.stageFinds[STAGE_INTEREST8]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST8]);
  auto int2 = to_string(fuzzStat.stageFinds[STAGE_INTEREST16]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST16]);
  auto int4 = to_string(fuzzStat.stageFinds[STAGE_INTEREST32]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST32]);
  auto knownInts = padStr(int1 + ", " + int2 + ", " + int4, 30);
  auto addrDict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_AO]) + "/" + to_string(mutation.stageCycles[STAGE_EXTRAS_AO]);
  auto dict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_UO]) + "/" + to_string(mutation.stageCycles[STAGE_EXTRAS_UO]);
  auto dictionary = padStr(dict1 + ", " + addrDict1, 30);
  auto hav1 = to_string(fuzzStat.stageFinds[STAGE_HAVOC]) + "/" + to_string(mutation.stageCycles[STAGE_HAVOC]);
  auto havoc = padStr(hav1, 30);
  auto pending = padStr(to_string(leaders.size() - fuzzStat.idx - 1), 5);
  auto fav = count_if(leaders.begin(), leaders.end(), [](const pair<string, Leader> &p) {
    return !p.second.item.fuzzedCount;
  });
  auto pendingFav = padStr(to_string(fav), 5);
  auto maxdepthStr = padStr(to_string(fuzzStat.maxdepth), 5);
  auto exceptionCount = padStr(to_string(uniqExceptions.size()), 5);
  auto predicateSize = padStr(to_string(predicates.size()), 5);
  auto tracebitsSize = padStr(to_string(tracebits.size()),5);
  auto contract = mainContract();
  //是否找到漏洞
  auto toResult = [](bool val) { return val ? "found" : "none "; };
  printf(cGRN Bold "%sAFL Solidity v0.0.1 (%s)" cRST "\n", padStr("", 10).c_str(), contract.contractName.substr(0, 20).c_str());
  printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV2 bV2 bV5 bV bTR "\n");
  printf(bH "      run time : %s " bH "\n", formatDuration(duration).data());
  printf(bH " last new path : %s " bH "\n",formatDuration(fromLastNewPath).data());
  printf(bLTR bV5 cGRN " stage progress " cRST bV5 bV10 bV2 bV bTTR bV2 cGRN " overall results " cRST bV2 bV5 bV2 bV2 bV bRTR "\n");
  printf(bH "  now trying : %s" bH " cycles done : %s" bH "\n", nowTrying.c_str(), cycleDone.c_str());
  printf(bH " stage execs : %s" bH "    branches : %s" bH "\n", stageExec.c_str(), numBranches.c_str());
  printf(bH " total execs : %s" bH "    coverage : %s" bH "\n", allExecs.c_str(), coverage.c_str());
  printf(bH "  exec speed : %s" bH "               %s" bH "\n", execSpeed.c_str(), padStr("", 15).c_str());
  printf(bH "  cycle prog : %s" bH "               %s" bH "\n", cycleProgress.c_str(), padStr("", 15).c_str());
  printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bV5 bV2 bV bBTR bV10 bV bTTR bV cGRN " path geometry " cRST bV2 bV2 bRTR "\n");
  printf(bH "   bit flips : %s" bH "     pending : %s" bH "\n", bitflip.c_str(), pending.c_str());
  printf(bH "  byte flips : %s" bH " pending fav : %s" bH "\n", byteflip.c_str(), pendingFav.c_str());
  printf(bH " arithmetics : %s" bH "   max depth : %s" bH "\n", arithmetic.c_str(), maxdepthStr.c_str());
  printf(bH "  known ints : %s" bH " uniq except : %s" bH "\n", knownInts.c_str(), exceptionCount.c_str());
  printf(bH "  dictionary : %s" bH "  predicates : %s" bH "\n", dictionary.c_str(), predicateSize.c_str());
  printf(bH "       havoc : %s" bH "   tracebits : %s" bH "\n", havoc.c_str(), tracebitsSize.c_str());
//  printf(bH "       havoc : %s" bH "               %s" bH "\n", havoc.c_str(), padStr("", 5).c_str());
  printf(bLTR bV5 cGRN " oracle yields " cRST bV bV10 bV5 bV bTTR bV2 bV10 bV bBTR bV bV2 bV5 bV5 bV2 bV2 bV5 bV bRTR "\n");
  printf(bH "            gasless send : %s " bH " dangerous delegatecall : %s " bH "\n", toResult(vulnerabilities[GASLESS_SEND]), toResult(vulnerabilities[DELEGATE_CALL]));
  printf(bH "      exception disorder : %s " bH "         freezing ether : %s " bH "\n", toResult(vulnerabilities[EXCEPTION_DISORDER]), toResult(vulnerabilities[FREEZING]));
  printf(bH "              reentrancy : %s " bH "       integer overflow : %s " bH "\n", toResult(vulnerabilities[REENTRANCY]), toResult(vulnerabilities[OVERFLOW]));
  printf(bH "    timestamp dependency : %s " bH "      integer underflow : %s " bH "\n", toResult(vulnerabilities[TIME_DEPENDENCY]), toResult(vulnerabilities[UNDERFLOW]));
  printf(bH " block number dependency : %s " bH "%s" bH "\n", toResult(vulnerabilities[NUMBER_DEPENDENCY]), padStr(" ", 32).c_str());
  printf(bBL bV20 bV2 bV10 bV5 bV2 bV bBTR bV10 bV5 bV20 bV2 bV2 bBR "\n");
}

void Fuzzer::writeStats(const Mutation &mutation) {
  auto contract = mainContract();
  stringstream ss;
  pt::ptree root;
  ofstream stats(contract.contractName + "/stats.json");
  //总时间
  root.put("duration", timer.elapsed());
  //总执行数
  root.put("totalExecs", fuzzStat.totalExecs);
  //执行速度
  root.put("speed", (double) fuzzStat.totalExecs / timer.elapsed());
  root.put("queueCycles", fuzzStat.queueCycle);
  root.put("uniqExceptions", uniqExceptions.size());
  pt::write_json(ss, root);
  stats << ss.str() << endl;
  stats.close();
}

/* Save data if interest */
//适者生存: 选择更好的数据
FuzzItem Fuzzer::saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis) {
  // data为测试用例
  auto revisedData = ContractABI::postprocessTestData(data);	//修订后数据
  FuzzItem item(revisedData);
  item.res = te.exec(revisedData, validJumpis);	//执行合约
  //Logger::debug(Logger::testFormat(item.data));
  fuzzStat.totalExecs ++;	//执行数
  //寻找新覆盖的分支
  for (auto tracebit: item.res.tracebits) {	//遍历执行结果的分支ID集合
	//之前未覆盖到的新分支
    if (!tracebits.count(tracebit)) {	//若分支ID集合中不包括执行结果中的分支ID
      // Remove leader
	  //在leaders里寻找和当前分支ID相同的元素并删除
      auto lIt = find_if(leaders.begin(), leaders.end(), [=](const pair<string, Leader>& p) { return p.first == tracebit;});
      if (lIt != leaders.end()) leaders.erase(lIt);
	  //在queues里寻找分支ID相同的元素,若没有则添加
      auto qIt = find_if(queues.begin(), queues.end(), [=](const string &s) { return s == tracebit; });
      if (qIt == queues.end()) queues.push_back(tracebit);
      // Insert leader
	  //添加leader
      item.depth = depth + 1;	//深度+1
      auto leader = Leader(item, 0);
      leaders.insert(make_pair(tracebit, leader));	//插入 cfg结点
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;	//记录最大深度
      fuzzStat.lastNewPath = timer.elapsed();	//记录推移时间
      Logger::debug("Cover new branch\nBranch ID: "  + tracebit);	//扫描到的分支ID
      Logger::debug("Testcase:\n" + Logger::testFormat(item.data));		//输出测试用例数据
    }
  }
  //寻找更好(distance更小)的分支
  for (auto predicateIt: item.res.predicates) {		//遍历执行结果的distance值
	//寻找和distance记录的分支ID相同的leader
    auto lIt = find_if(leaders.begin(), leaders.end(), [=](const pair<string, Leader>& p) { return p.first == predicateIt.first;});
    if (
        lIt != leaders.end() // Found Leader	找到cfg结点, 之前已经发现
        && lIt->second.comparisonValue > 0 // Not a covered branch	之前记录的差值>0, 证明该分支仍未被覆盖
        && lIt->second.comparisonValue > predicateIt.second // ComparisonValue is better	当前的差值小于原本记录的差值, 当前更好
    ) {
      // Debug now
      Logger::debug("Found better test case for uncovered branch\nBranch ID: " + predicateIt.first);	//记录最新的测试用例跟踪位
      Logger::debug("prev: " + lIt->second.comparisonValue.str());	//原本差值
      Logger::debug("now : " + predicateIt.second.str());	//更新后差值
      // Stop debug
      leaders.erase(lIt); // Remove leader	移除cfg结点
      item.depth = depth + 1;	//深度+1
      auto leader = Leader(item, predicateIt.second);		//将更新后的cfg结点插入
      leaders.insert(make_pair(predicateIt.first, leader)); // Insert leader
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;		//记录最大深度
      fuzzStat.lastNewPath = timer.elapsed();	//更新推移时间
      Logger::debug("Testcase:\n" + Logger::testFormat(item.data));		//记录更新后测试用例数据
    } else if (lIt == leaders.end()) {		//未找到leader, 证明该路径之前未被发现
      auto leader = Leader(item, predicateIt.second);
      item.depth = depth + 1;
      leaders.insert(make_pair(predicateIt.first, leader)); // Insert cfg结点
      queues.push_back(predicateIt.first);	//Insert queues 插入到queue中
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;		//深度+1
      fuzzStat.lastNewPath = timer.elapsed();	//推移时间
      // Debug
      Logger::debug("Found new uncovered branch");
      Logger::debug("Branch ID: " + predicateIt.first);		//chg
      Logger::debug("now: " + predicateIt.second.str());	//当前distance
      Logger::debug("Testcase:\n" + Logger::testFormat(item.data));		//测试用例数据
    }
  }
  //更新值
  updateExceptions(item.res.uniqExceptions);
  updateTracebits(item.res.tracebits);	//更新tracebit
  updatePredicates(item.res.predicates);
  return item;
}

/* Stop fuzzing */
//停止模糊测试
void Fuzzer::stop() {
  Logger::debug("== TEST ==");
  unordered_map<uint64_t, uint64_t> brs;
  //遍历所有已发现的分支
  for (auto it : leaders) {		//遍历分支
    auto pc = stoi(splitString(it.first, ':')[0]);	//pc值
    // Covered
    if (it.second.comparisonValue == 0) {	//分支被覆盖
      if (brs.find(pc) == brs.end()) {
        brs[pc] = 1;
      } else {
        brs[pc] += 1;
      }
    }
    Logger::debug("Branch ID: " + it.first);	//分支ID
    Logger::debug("ComparisonValue: " + it.second.comparisonValue.str());	//差值
    Logger::debug("Testcase:\n" + Logger::testFormat(it.second.item.data));		//测试用例数据
  }
  Logger::debug("== END TEST ==");
  for (auto it : snippets) {	//遍历代码片段
    if (brs.find(it.first) == brs.end()) {	//找到未到达分支
      Logger::info(">> Unreachable");
      Logger::info(it.second);	//记录未到达源码
    } else {
      if (brs[it.first] == 1) {
        Logger::info(">> Haft");
        Logger::info(it.second);
      } else {
        Logger::info(">> Full");
        Logger::info(it.second);
      }
    }
  }
  exit(1);
}

/* Start fuzzing */
//开始模糊测试
void Fuzzer::start() {
  TargetContainer container;
  Dictionary codeDict,	//合约中push的值(数据值)
	  addressDict;	//攻击合约地址字典
  unordered_set<u64> showSet;
  for (auto contractInfo : fuzzParam.contractInfo) {	//遍历合约信息: 
	//攻击合约标识
    auto isAttacker = contractInfo.contractName.find(fuzzParam.attackerName) != string::npos;
    if (!contractInfo.isMain && !isAttacker) continue;	//不是测试合约和攻击合约则跳过
    ContractABI ca(contractInfo.abiJson, contractInfo.contractName);	//abi
    auto bin = fromHex(contractInfo.bin);	//bin
    auto binRuntime = fromHex(contractInfo.binRuntime);	//runtime-bin
    // Accept only valid jumpis
	//仅接收有效的Jumpi
    auto executive = container.loadContract(bin, ca);	//加载执行合约
    if (!contractInfo.isMain) {		//攻击合约
      /* Load Attacker agent contract */
      auto data = ca.randomTestcase();	//初始化测试用例数据
      auto revisedData = ContractABI::postprocessTestData(data);
      executive.deploy(revisedData, EMPTY_ONOP);	//部署合约
      addressDict.fromAddress(executive.addr.asBytes());	//返回地址
    } else {	//待测合约
      auto contractName = contractInfo.contractName;	//合约名
      boost::filesystem::remove_all(contractName);		//删除合约名的文件夹
      boost::filesystem::create_directory(contractName);	//创建合约名的文件夹
      codeDict.fromCode(bin);		//将push的值放入字典
      auto bytecodeBranch = BytecodeBranch(contractInfo);
      auto validJumpis = bytecodeBranch.findValidJumpis();
      snippets = bytecodeBranch.snippets;	//Jumpi源码片段
	  //若有效的Jumpi数目为0, 则停止模糊测试
      if (!(get<0>(validJumpis).size() + get<1>(validJumpis).size())) {
        cout << "No valid jumpi" << endl;
        stop();
      }

      cout<<ca.contractName<<endl;
      saveIfInterest(executive, ca.randomTestcase(), 0, validJumpis);
      ca.updateTestcaseCnt();
	  for (unsigned i = 0; i < ca.testcaseCnt; ++i) {
//          printf("testcase\n");
          auto data = ca.initTestcase();
//          cout<<Logger::testFormat(data).c_str()<<endl;
          saveIfInterest(executive, data, 0, validJumpis);
	  }


      int originHitCount = leaders.size();	//发现的分支数
      // No branch
      if (!originHitCount) {	//无发现的分支则停止
        cout << "No branch" << endl;
        stop();
      }
      // There are uncovered branches or not
	  //lambda: 判断是否未覆盖到
      auto fi = [&](const pair<string, Leader> &p) { return p.second.comparisonValue != 0;};
      auto numUncoveredBranches = count_if(leaders.begin(), leaders.end(), fi);		//统计未覆盖到的分支数
      if (!numUncoveredBranches) {	//无未覆盖分支(覆盖率100%)
        auto curItem = (*leaders.begin()).second.item;	//当前测试项目
        Mutation mutation(curItem, make_tuple(codeDict, addressDict));
        vulnerabilities = container.analyze();		//漏洞分析
		//报告测试结果
        switch (fuzzParam.reporter) {	//判断报告方式
          case TERMINAL: {	//终端
            showStats(mutation, validJumpis);
            break;
          }
          case JSON: {	//json
            writeStats(mutation);
            break;
          }
          case BOTH: {	//两者
            showStats(mutation, validJumpis);
            writeStats(mutation);
            break;
          }
        }
        stop();	//停止模糊测试
      }
      // Jump to fuzz loop
	  //针对已发现分支中未覆盖的分支进行循环测试
      while (true) {
        auto leaderIt = leaders.find(queues[fuzzStat.idx]);
        auto curItem = leaderIt->second.item;
        auto comparisonValue = leaderIt->second.comparisonValue;
        if (comparisonValue != 0) {		//差值不为零(未覆盖)
          Logger::debug(" == Leader ==");
          Logger::debug("Branch \t\t\t\t " + leaderIt->first);	//分支pc
          Logger::debug("Comp \t\t\t\t " + comparisonValue.str());	//差值
          Logger::debug("Fuzzed \t\t\t\t " + to_string(curItem.fuzzedCount));	//已测试次数
          Logger::debug("Testcase \n" + Logger::testFormat(curItem.data));	//测试用例数据
        }
        Mutation mutation(curItem, make_tuple(codeDict, addressDict));	//突变
		//lambda: 选择数据并存储报告
		auto save = [&](bytes data) {
		  //选择数据
          auto item = saveIfInterest(executive, data, curItem.depth, validJumpis);
          /* Show every one second */
          u64 duration = timer.elapsed();
          if (!showSet.count(duration)) {
            showSet.insert(duration);
            if (duration % fuzzParam.analyzingInterval == 0) {	//达到分析间隔
              vulnerabilities = container.analyze();	//漏洞分析
            }
			// 报告测试结果
            switch (fuzzParam.reporter) {
              case TERMINAL: {
                showStats(mutation, validJumpis);
                break;
              }
              case JSON: {
                writeStats(mutation);
                break;
              }
              case BOTH: {
                showStats(mutation, validJumpis);
                writeStats(mutation);
                break;
              }
            }
          }	//if (!showSet.count(duration))
          /* Stop program */
          u64 speed = (u64)(fuzzStat.totalExecs / timer.elapsed());	//速度=执行合约数/推移时间
		  //若到达时间||执行速度小于10||存储的distance值为空
          if (timer.elapsed() > fuzzParam.duration || speed <= 10 || !predicates.size()) {
            vulnerabilities = container.analyze();	//漏洞分析
			//报告测试结果
            switch(fuzzParam.reporter) {
              case TERMINAL: {
                showStats(mutation, validJumpis);
                break;
              }
              case JSON: {
                writeStats(mutation);
                break;
              }
              case BOTH: {
                showStats(mutation, validJumpis);
                writeStats(mutation);
                break;
              }
            }
            stop();		//停止测试
          }
          return item;
        };	//lambda-save

        // If it is uncovered branch
		//若为未覆盖分支
        if (comparisonValue != 0) {
          // Haven't fuzzed before
		  //未曾模糊测试过
          if (!curItem.fuzzedCount) {
			//变异
            Logger::debug("SingleWalkingBit");
            mutation.singleWalkingBit(save);
            fuzzStat.stageFinds[STAGE_FLIP1] += leaders.size() - originHitCount;
            originHitCount = leaders.size();

            Logger::debug("TwoWalkingBit");
            mutation.twoWalkingBit(save);
            fuzzStat.stageFinds[STAGE_FLIP2] += leaders.size() - originHitCount;
            originHitCount = leaders.size();

            Logger::debug("FourWalkingBtit");
            mutation.fourWalkingBit(save);
            fuzzStat.stageFinds[STAGE_FLIP4] += leaders.size() - originHitCount;
            originHitCount = leaders.size();

            Logger::debug("SingleWalkingByte");
            mutation.singleWalkingByte(save);
            fuzzStat.stageFinds[STAGE_FLIP8] += leaders.size() - originHitCount;
            originHitCount = leaders.size();

            Logger::debug("TwoWalkingByte");
            mutation.twoWalkingByte(save);
            fuzzStat.stageFinds[STAGE_FLIP16] += leaders.size() - originHitCount;
            originHitCount = leaders.size();

            Logger::debug("FourWalkingByte");
            mutation.fourWalkingByte(save);
            fuzzStat.stageFinds[STAGE_FLIP32] += leaders.size() - originHitCount;
            originHitCount = leaders.size();

            //Logger::debug("SingleArith");
            //mutation.singleArith(save);
            //fuzzStat.stageFinds[STAGE_ARITH8] += leaders.size() - originHitCount;
            //originHitCount = leaders.size();

            //Logger::debug("TwoArith");
            //mutation.twoArith(save);
            //fuzzStat.stageFinds[STAGE_ARITH16] += leaders.size() - originHitCount;
            //originHitCount = leaders.size();

            //Logger::debug("FourArith");
            //mutation.fourArith(save);
            //fuzzStat.stageFinds[STAGE_ARITH32] += leaders.size() - originHitCount;
            //originHitCount = leaders.size();

            //Logger::debug("SingleInterest");
            //mutation.singleInterest(save);
            //fuzzStat.stageFinds[STAGE_INTEREST8] += leaders.size() - originHitCount;
            //originHitCount = leaders.size();

            //Logger::debug("TwoInterest");
            //mutation.twoInterest(save);
            //fuzzStat.stageFinds[STAGE_INTEREST16] += leaders.size() - originHitCount;
            //originHitCount = leaders.size();

            //Logger::debug("FourInterest");
            //mutation.fourInterest(save);
            //fuzzStat.stageFinds[STAGE_INTEREST32] += leaders.size() - originHitCount;
            //originHitCount = leaders.size();

            //Logger::debug("overwriteDict");
            //mutation.overwriteWithDictionary(save);
            //fuzzStat.stageFinds[STAGE_EXTRAS_UO] += leaders.size() - originHitCount;
            //originHitCount = leaders.size();

            Logger::debug("overwriteAddress");
            mutation.overwriteWithAddressDictionary(save);
            fuzzStat.stageFinds[STAGE_EXTRAS_AO] += leaders.size() - originHitCount;
            originHitCount = leaders.size();

            Logger::debug("havoc");
            mutation.havoc(save);
            fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
            originHitCount = leaders.size();
          } else {	//模糊测试过
            Logger::debug("havoc");
            mutation.havoc(save);
            fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
            originHitCount = leaders.size();
            Logger::debug("Splice");
            vector<FuzzItem> items = {};
            for (auto it : leaders) items.push_back(it.second.item);
            if (mutation.splice(items)) {
              Logger::debug("havoc");
              mutation.havoc(save);
              fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - originHitCount;
              originHitCount = leaders.size();
            }
          }
        }
        leaderIt->second.item.fuzzedCount += 1;		//测试次数+1
        fuzzStat.idx = (fuzzStat.idx + 1) % leaders.size();		//测试序号+1
        if (fuzzStat.idx == 0) fuzzStat.queueCycle ++;	//循环轮数+1
      }
    }
  }
}
