#include <set>
#include "Dictionary.h"

using namespace std;
using namespace eth;

namespace fuzzer {
  //将地址值放入字典
  void Dictionary::fromAddress(bytes data) {
    ExtraData d;
    d.data = data;
    extras.push_back(d);
  }

  //将push的值放入字典
  void Dictionary::fromCode(bytes code) {
    int pc = 0;
    int size = code.size();
    struct bytesComparation {
      bool operator ()(const bytes a, const bytes b) {
		//ab大小相同时比较所有字节
        if (a.size() == b.size()) return memcmp(b.data(), a.data(), a.size()) > 0;
        return b.size() > a.size();
      }
    };
    set<bytes, bytesComparation> values;
    while (pc < size) {
      if (code[pc] > 0x5f && code[pc] < 0x80) {	//push指令
        /* PUSH instruction */
        int jumpNum = code[pc] - 0x5f;	//push的字节数
        bytes value = bytes(code.begin() + pc + 1, code.begin() + pc + 1 + jumpNum);	//push的数据
        values.insert(value);
        pc += jumpNum;
      }
      pc += 1;
    }
    for (auto value : values) {
      ExtraData d;
      d.data = value;
      extras.push_back(d);
    }
  }
}
