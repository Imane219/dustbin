#pragma once
#include <vector>
#include "Common.h"

using namespace dev;
using namespace std;

namespace fuzzer {
  using Accounts = vector<tuple<bytes, u160, u256, bool>>;		//  ,地址,余额,发送方(isSender)
  using FakeBlock = tuple<bytes, int64_t, int64_t>;		// , blocknumber, timestamp

  //数据类型
  struct DataType {
    bytes value;	//数据值
    bool padLeft;	//填充方式
    bool isDynamic;	//动态数据
    DataType(){};
    DataType(bytes value, bool padLeft, bool isDynamic);
    bytes payload();
    bytes header();
  };

  //参数定义
  struct TypeDef {
    string name;	//类型名
    string fullname;	//全名
    string realname;	//真名
    bool padLeft;	//填充方式(string && bytes 右填充)
    bool isDynamic;	//动态数据(string或bytes)
    bool isDynamicArray;	//最外层是动态数组
    bool isSubDynamicArray;	//二维数组内层是动态数组
    TypeDef(string name);
    void addValue(bytes v);
    void addValue(vector<bytes> vs);
    void addValue(vector<vector<bytes>> vss);
    static string toFullname(string name);
    static string toRealname(string name);
    vector<int> extractDimension(string name);
    vector<int> dimensions;	//维度
    DataType dt;	//单个变量参数数据
    vector<DataType> dts;	//一维数组参数数据
    vector<vector<DataType>> dtss;	//二维数组参数数据
  };

  //函数定义
  struct FuncDef {
    string name;	//函数名
    bool payable;	//是否可交易
    vector<TypeDef> tds;	//入口参数vector
    FuncDef(){};
	//函数定义
    FuncDef(string name, vector<TypeDef> tds, bool payable);
  };

  //合约ABI
  class ContractABI {
    //账户集: 包括测试用例中的发送方地址, 以及合约中出现的address参数的值
    vector<bytes> accounts;		
    bytes block;	//区块号
    public:
      vector<FuncDef> fds;	//合约函数vector
      ContractABI(){};
      ContractABI(string abiJson, string name);
      /* encoded ABI of contract constructor */
      //编码合约构造函数
      bytes encodeConstructor();
      /* encoded ABI of contract functions */
	  //对合约函数进行编码: 函数选择器+函数参数列表数据值
      vector<bytes> encodeFunctions();
      /* Create random testcase for fuzzer */
	  //初始化测试用例
      bytes randomTestcase();
      /* Update then call encodeConstructor/encodeFunction to feed to evm */
      //从测试用例中更新数据到参数值中
      void updateTestData(bytes data);
      /* Standard Json */
      string toStandardJson();
      uint64_t totalFuncs();
      //解码账户,从测试用例提取(账户余额,地址)
      Accounts decodeAccounts();
      //编码区块, 从测试用例提取区块号,时间戳
      FakeBlock decodeBlock();
      //返回合约函数是否是可交易的
      bool isPayable(string name);
      //获取发送者账户地址
      Address getSender();
	  //对不同类型参数进行编码
      static bytes encodeTuple(vector<TypeDef> tds);
      static bytes encode2DArray(vector<vector<DataType>> dtss, bool isDynamic, bool isSubDynamic);
      static bytes encodeArray(vector<DataType> dts, bool isDynamicArray);
      static bytes encodeSingle(DataType dt);
      static bytes functionSelector(string name, vector<TypeDef> tds);
      //在将生成的数据发送到vm的msg.sender地址之前验证其生成的数据不能为0（32-64）
      static bytes postprocessTestData(bytes data);

      unsigned char testcaseCnt = 0;
      unsigned char testcaseIdx = 0;
      bytes dynamicIdx;
	  bytes initTestcase();
      void updateTestcaseCnt();
      string contractName;

  private:
      void updateDynamicIdx();
  };
}
