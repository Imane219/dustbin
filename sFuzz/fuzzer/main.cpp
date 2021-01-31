#include <iostream>
#include <libfuzzer/Fuzzer.h>
#include "Utils.h"

using namespace std;
using namespace fuzzer;

static int DEFAULT_MODE = AFL;
static int DEFAULT_DURATION = 120; // 2 mins
static int DEFAULT_REPORTER = JSON;
static int DEFAULT_ANALYZING_INTERVAL = 5; // 5 sec
static string DEFAULT_CONTRACTS_FOLDER = "contracts/";
static string DEFAULT_ASSETS_FOLDER = "assets/";
static string DEFAULT_ATTACKER = "ReentrancyAttacker";

int main(int argc, char* argv[]) {
  /* Run EVM silently */
  dev::LoggingOptions logOptions;
  logOptions.verbosity = VerbositySilent;
  dev::setupLogging(logOptions);
  /* Program options */
  int mode = DEFAULT_MODE;
  int duration = DEFAULT_DURATION;
  int reporter = DEFAULT_REPORTER;
  string contractsFolder = DEFAULT_CONTRACTS_FOLDER;	//待测合约目录
  string assetsFolder = DEFAULT_ASSETS_FOLDER;	//攻击合约目录
  string jsonFile = "";
  string contractName = "";
  string sourceFile = "";
  string attackerName = DEFAULT_ATTACKER;	//攻击合约设置
  po::options_description desc("Allowed options");	//声明所有允许的选项
  po::variables_map vm;		//保存各选项的值
  
  desc.add_options()
    ("help,h", "produce help message")
    ("contracts,c", po::value(&contractsFolder), "contract's folder path")
    ("generate,g", "g fuzzMe script")
    ("assets,a", po::value(&assetsFolder), "asset's folder path")
    ("file,f", po::value(&jsonFile), "fuzz a contract")
    ("name,n", po::value(&contractName), "contract name")
    ("source,s", po::value(&sourceFile), "source file path")
    ("mode,m", po::value(&mode), "choose mode: 0 - AFL ")
    ("reporter,r", po::value(&reporter), "choose reporter: 0 - TERMINAL | 1 - JSON")
    ("duration,d", po::value(&duration), "fuzz duration")
    ("attacker", po::value(&attackerName), "choose attacker: NormalAttacker | ReentrancyAttacker");
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm);
  /* Show help message */
  //输出帮助信息
  if (vm.count("help")) showHelp(desc);
  /* Generate working scripts */
  //生成工作脚本
  if (vm.count("generate")) {
    std::ofstream fuzzMe("fuzzMe");
    fuzzMe << "#!/bin/bash" << endl;
	//编译合约
    fuzzMe << compileSolFiles(contractsFolder);
    fuzzMe << compileSolFiles(assetsFolder);
    fuzzMe << fuzzJsonFiles(contractsFolder, assetsFolder, duration, mode, reporter, attackerName);
    fuzzMe.close();
    showGenerate();
    return 0;
  }
  /* Fuzz a single contract */
  //模糊测试单个合约
  if (vm.count("file") && vm.count("name") && vm.count("source")) {
    FuzzParam fuzzParam;
    auto contractInfo = parseAssets(assetsFolder);
    contractInfo.push_back(parseSource(sourceFile, jsonFile, contractName, true));
    fuzzParam.contractInfo = contractInfo;
    fuzzParam.mode = (FuzzMode) mode;
    fuzzParam.duration = duration;
    fuzzParam.reporter = (Reporter) reporter;
    fuzzParam.analyzingInterval = DEFAULT_ANALYZING_INTERVAL;
    fuzzParam.attackerName = attackerName;
    Fuzzer fuzzer(fuzzParam);
    cout << ">> Fuzz " << contractName << endl;
    fuzzer.start();
    return 0;
  }
  return 0;
}
