#include "Logger.h"

using namespace std;

namespace fuzzer {
  const string path = "./logger/";
  ofstream Logger::debugFile = ofstream(path + "debug.txt", ios_base::app);
  ofstream Logger::infoFile = ofstream(path + "info.txt", ios_base::app);

  bool Logger::enabled = true;

  void Logger::debug(string str) {
    if (enabled) {
      debugFile << str << endl;
    }
  }

  //记录信息
  void Logger::info(string str) {
    if (enabled) {
      infoFile << str << endl;
    }
  }

  //输出数据
  string Logger::testFormat(bytes data) {
    auto idx = 0;
    stringstream ss;
    while (idx < data.size()) {
      bytes d(data.begin() + idx, data.begin() + idx + 32);
      idx += 32;
      ss << toHex(d) << endl;
    }
    return ss.str();
  }
}
