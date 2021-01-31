#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <libfuzzer/Fuzzer.h>

using namespace std;
using namespace fuzzer;
using namespace boost::filesystem;
namespace pt = boost::property_tree;
namespace po = boost::program_options;  //存取来自命令行、配置文件或其它来源的配置数据

//解析json文件
ContractInfo parseJson(string jsonFile, string contractName, bool isMain) {
  std::ifstream file(jsonFile);
  if (!file.is_open()) {	//文件打开失败
    stringstream output;
    output << "[x] File " + jsonFile + " is not found" << endl;
    cout << output.str();
    exit(0);
  }
  pt::ptree root;
  pt::read_json(jsonFile, root);
  string fullContractName = "";
  for (auto key : root.get_child("contracts")) {
    if (boost::ends_with(key.first, contractName)) {
      fullContractName = key.first;
      break;
    }
  }
  if (!fullContractName.length()) {	//无合约
    cout << "[x] No contract " << contractName << endl;
    exit(0);
  }
  //设置属性结点的路径
  pt::ptree::path_type abiPath("contracts|"+ fullContractName +"|abi", '|');
  pt::ptree::path_type binPath("contracts|"+ fullContractName +"|bin", '|');
  pt::ptree::path_type binRuntimePath("contracts|" + fullContractName + "|bin-runtime", '|');
  pt::ptree::path_type srcmapPath("contracts|" + fullContractName + "|srcmap", '|');
  pt::ptree::path_type srcmapRuntimePath("contracts|" + fullContractName + "|srcmap-runtime", '|');
  ContractInfo contractInfo;
  contractInfo.isMain = isMain;
  contractInfo.abiJson = root.get<string>(abiPath);
  contractInfo.bin = root.get<string>(binPath);
  contractInfo.binRuntime = root.get<string>(binRuntimePath);
  contractInfo.srcmap = root.get<string>(srcmapPath);
  contractInfo.srcmapRuntime = root.get<string>(srcmapRuntimePath);
  contractInfo.contractName = fullContractName;
  for (auto it : root.get_child("sources")) {
    auto ast = it.second.get_child("AST");
    vector<pt::ptree> stack = {ast};
    while (stack.size() > 0) {
      auto item = stack[stack.size() - 1];
      stack.pop_back();
	  //将函数中属性为constant的将其源码放入constantFunctionSrcmap
      if (item.get<string>("name") == "FunctionDefinition") {
        if (item.get<bool>("attributes.constant")) {
          contractInfo.constantFunctionSrcmap.push_back(item.get<string>("src"));
        }
      }
      if (item.get_child_optional("children")) {
        for (auto it : item.get_child("children")) {
          stack.push_back(it.second);
        }
      }
    }
  }
  return contractInfo;
}

//解析待测合约源码
ContractInfo parseSource(string sourceFile, string jsonFile, string contractName, bool isMain) {
  std::ifstream file(sourceFile);
  if (!file.is_open()) {	//文件打开失败
    stringstream output;
    output << "[x] File " + jsonFile + " is not found" << endl;
    cout << output.str();
    exit(0);
  }
  auto contractInfo = parseJson(jsonFile, contractName, isMain);
  std::string sourceContent((std::istreambuf_iterator<char>(file)),(std::istreambuf_iterator<char>()));
  contractInfo.source = sourceContent;	//源码
  return contractInfo;
}

//转换为合约名
string toContractName(directory_entry file) {
  string filePath = file.path().string();
  string fileName = file.path().filename().string();
  string fileNameWithoutExtension = fileName.find(".") != string::npos
  ? fileName.substr(0, fileName.find("."))
  : fileName;	//无扩展名的合约名
  string contractName = fileNameWithoutExtension.find("_0x") != string::npos
  ? fileNameWithoutExtension.substr(0, fileNameWithoutExtension.find("_0x"))
  : fileNameWithoutExtension;
  return contractName;
}

//遍历文件夹中给定扩展名文件执行函数
void forEachFile(string folder, string extension, function<void (directory_entry)> cb) {
  path folderPath(folder);	//文件夹路径
  for (auto& file : boost::make_iterator_range(directory_iterator(folderPath), {})) {
	//对子目录中文件递归执行
    if (is_directory(file.status())) forEachFile(file.path().string(), extension, cb);
	//对文件执行函数
	if (!is_directory(file.status()) && boost::ends_with(file.path().string(), extension)) cb(file);
  }
}

//编译合约源文件
string compileSolFiles(string folder) {
  stringstream ret;
  //对文件夹中每个sol文件执行solc进行编译
  forEachFile(folder, ".sol", [&](directory_entry file) {
    string filePath = file.path().string();
    ret << "solc";
    ret << " --combined-json abi,bin,bin-runtime,srcmap,srcmap-runtime,ast " + filePath;
    ret << " > " + filePath + ".json";
    ret << endl;
  });
  return ret.str();
}

//生成模糊测试运行命令
string fuzzJsonFiles(string contracts, string assets, int duration, int mode, int reporter, string attackerName) {
  stringstream ret;
  unordered_set<string> contractNames;
  /* search for sol file */
  //对每个合约生成sfuzz命令
  forEachFile(contracts, ".sol", [&](directory_entry file) {
    auto filePath = file.path().string();
    auto contractName = toContractName(file);
    if (contractNames.count(contractName)) return;
    ret << "./fuzzer";
    ret << " --file " + filePath + ".json";
    ret << " --source " + filePath;
    ret << " --name " + contractName;
    ret << " --assets " + assets;
    ret << " --duration " + to_string(duration);
    ret << " --mode " + to_string(mode);
    ret << " --reporter " + to_string(reporter);
    ret << " --attacker " + attackerName;
    ret << endl;
  });
  return ret.str();
}

//解析攻击合约,返回合约信息列表
vector<ContractInfo> parseAssets(string assets) {
  vector<ContractInfo> ls;
  //处理assets文件夹中每个json文件
  forEachFile(assets, ".json", [&](directory_entry file) {
    auto contractName = toContractName(file);
    auto jsonFile = file.path().string();
    ls.push_back(parseJson(jsonFile, contractName, false));
  });
  return ls;
}

//输出命令行帮助信息
void showHelp(po::options_description desc) {
  stringstream output;
  output << desc << endl;
  output << "Example:" << endl;
  output << "> Generate executable scripts" << endl;
  output << "  " cGRN "./fuzzer -g" cRST << endl;
  cout << output.str();
}

//输出生成信息
void showGenerate() {
  stringstream output;
  output << cGRN "> Created \"fuzzMe\"" cRST "\n";
  output << cGRN "> To fuzz contracts:" cRST "\n";
  output << "  chmod +x fuzzMe\n";
  output << "  ./fuzzMe\n";
  cout << output.str();
}
