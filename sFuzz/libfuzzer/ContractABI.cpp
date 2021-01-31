#include <regex>
#include "ContractABI.h"

using namespace std;
namespace pt = boost::property_tree;

namespace fuzzer {
  FuncDef::FuncDef(string name, vector<TypeDef> tds, bool payable) {
	this->name = name;
	this->tds = tds;
	this->payable = payable;
  }

  //编码区块, 从测试用例提取区块号,时间戳
  FakeBlock ContractABI::decodeBlock() {
	if (!block.size()) throw "Block is empty";
	auto numberInBytes = bytes(block.begin(), block.begin() + 8);	//区块号
	auto timestampInBytes = bytes(block.begin() + 8, block.begin() + 16);	//时间戳
	auto number = u64("0x" + toHex(numberInBytes));
	auto timestamp = u64("0x" + toHex(timestampInBytes));
	return make_tuple(block, (int64_t)number, (int64_t)timestamp);
  }

  //获取发送者账户地址
  Address ContractABI::getSender() {
	auto accounts = decodeAccounts();
	for (auto account : accounts) {	//遍历账户
	  if (get<3>(account)) return get<1>(account);	//获取发送者账户地址
	}
  }

  //解码账户,从测试用例提取(账户余额,地址)
  Accounts ContractABI::decodeAccounts() {
	unordered_set<string> accountSet;
	Accounts ret;
	auto isSender = true;
	for (auto account : accounts) {		//遍历所有账户
	  bytes balanceInBytes(account.begin(), account.begin() + 12);	//账户余额
	  bytes addressInBytes(account.begin() + 12, account.end());	//账户地址
	  u256 balance = u256("0x" + toHex(balanceInBytes));
	  u160 address = u160("0x" + toHex(addressInBytes));
	  auto pair = accountSet.insert(toHex(addressInBytes));		//添加账户地址
	  if (pair.second) {	//若第一次添加到集合则为true
		ret.push_back(make_tuple(account, address, balance, isSender));	//添加到账户
		isSender = false;	//第一个账户为发送者(攻击合约),其余不为
	  }
	}
	return ret;
  }
  
  uint64_t ContractABI::totalFuncs() {
	return count_if(fds.begin(), fds.end(), [](FuncDef fd) {
	  return fd.name != "";
	});
  }
  
  string ContractABI::toStandardJson() {
	stringstream os;
	pt::ptree funcs;
	pt::ptree root;
	for (auto fd : this->fds) {
	  pt::ptree func;
	  pt::ptree inputs;
	  func.put("name", fd.name);
	  for (auto td : fd.tds) {
		pt::ptree input;
		input.put("type", td.name);
		switch (td.dimensions.size()) {
		  case 0: {
			input.put("value", "0x" + toHex(td.dt.value));
			break;
		  }
		  case 1: {
			pt::ptree values;
			for (auto dt : td.dts) {
			  pt::ptree value;
			  value.put_value("0x" + toHex(dt.value));
			  values.push_back(make_pair("", value));
			}
			input.add_child("value", values);
			break;
		  }
		  case 2: {
			pt::ptree valuess;
			for (auto dts : td.dtss) {
			  pt::ptree values;
			  for (auto dt : dts) {
				pt::ptree value;
				value.put_value("0x" + toHex(dt.value));
				values.push_back(make_pair("", value));
			  }
			  valuess.push_back(make_pair("", values));
			}
			input.add_child("value", valuess);
			break;
		  }
		}
		inputs.push_back(make_pair("", input));
	  }
	  func.add_child("inputs", inputs);
	  funcs.push_back(make_pair("", func));
	}
	root.add_child("functions", funcs);
	/* Accounts */
	unordered_set<string> accountSet; // to check exists
	pt::ptree accs;
	auto accountInTuples = decodeAccounts();
	for (auto account : accountInTuples) {
	  auto accountInBytes = get<0>(account);
	  auto balance = get<2>(account);
	  auto address = bytes(accountInBytes.begin() + 12, accountInBytes.end());
	  pt::ptree acc;
	  acc.put("address", "0x" + toHex(address));
	  acc.put("balance", balance);
	  accs.push_back(make_pair("", acc));
	}
	root.add_child("accounts", accs);
	pt::write_json(os, root);
	return os.str();
  }
  /*
   * Validate generated data before sending it to vm
   * msg.sender address can not be 0 (32 - 64)
   */
  //在将生成的数据发送到vm的msg.sender地址之前验证其生成的数据不能为0（32-64） chg
  bytes ContractABI::postprocessTestData(bytes data) {
	auto sender = u256("0x" + toHex(bytes(data.begin() + 12, data.begin() + 32)));
	auto balance = u256("0x" + toHex(bytes(data.begin(), data.begin() + 12)));
	if (!balance) data[0] = 0xff;	//余额为0设置最高位为ff
	if (!sender) data[31] = 0xf0;	//发送者为0设置攻击合约地址
	return data;
  }

  //从测试用例中更新数据到参数值中	chg
  void ContractABI::updateTestData(bytes data) {
	/* Detect dynamic len by consulting first 32 bytes */
	//通过查询测试用例前32字节检测动态长度
	int lenOffset = 0;	//动态参数长度对应位向量偏移指针
	//lambda:查询动态参数真正长度(元素个数)
	auto consultRealLen = [&]() {
	  //int len = data[lenOffset];
	  //lenOffset = (lenOffset + 1) % 32;
	  return dynamicIdx[lenOffset++];
	};
	/* Container of dynamic len */
    //lambda:查询整个数组的长度(bit)
	auto consultContainerLen = [](int realLen) {
	  if (!(realLen % 32)) return realLen;
	  return (realLen / 32 + 1) * 32;
	};
	/* Pad to enough data before decoding */
	//解码前填充足够的数据
	//int offset = 96;	//函数参数偏移指针,96为函数参数在测试用例中的起始位置
	int offset = 64;	//函数参数偏移指针,函数参数在测试用例中的起始位置
	//lambda: 填充数据
	auto padLen = [&](int singleLen) {
	  int fitLen = offset + singleLen;
	  while ((int)data.size() < fitLen) data.push_back(0);	//若data的长度不够实际需要的长度, 则填充0
	};
	//清空区块号和账户
	block.clear();
	accounts.clear();
	//交易发送方位向量
	//auto senderInBytes = bytes(data.begin() + 32, data.begin() + 64);
	auto senderInBytes = bytes(data.begin(), data.begin() + 32);
	//区块号
	block = bytes(data.begin() + 32, data.begin() + 64);
	accounts.push_back(senderInBytes);	//发送方位向量添加到账户vector中
	for (auto &fd : this->fds) {	//遍历每个函数
	  for (auto &td : fd.tds) {	//遍历函数的每个入口参数
		switch (td.dimensions.size()) {	//判断参数维度
		  case 0: {		//单个变量
			//确定动态参数长度及比特数
			int realLen = td.isDynamic ? consultRealLen() : 32;
			int containerLen = consultContainerLen(realLen);
			/* Pad to enough bytes to read */
			padLen(containerLen);	//填充数据
			/* Read from offset ... offset + realLen */
			//读取填充后的参数值
			bytes d(data.begin() + offset, data.begin() + offset + realLen);
			/* If address, extract account */
			//若参数为地址, 则提取参数作到账户(地址)
			if (boost::starts_with(td.name, "address")) {
			  accounts.push_back(d);
			}
			td.addValue(d);
			/* Ignore (containerLen - realLen) bytes */
			offset += containerLen;		//偏移指针后移
			break;
		  }
		  case 1: {		//一维数组
			vector<bytes> ds;	//参数值vector
			//元素个数
			int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
			for (int i = 0; i < numElem; i += 1) {	//遍历每个元素
			  int realLen = td.isDynamic ? consultRealLen() : 32;	//确定动态元素个数
			  int containerLen = consultContainerLen(realLen);	//确定比特数
			  padLen(containerLen);	//填充数据
			  bytes d(data.begin() + offset, data.begin() + offset + realLen);
			  ds.push_back(d);	//添加数据
			  offset += containerLen;	//偏移指针后移
			}
			/* If address, extract account */
			//若参数为地址则提取到账户
			if (boost::starts_with(td.name, "address")) {
			  accounts.insert(accounts.end(), ds.begin(), ds.end());
			}
			td.addValue(ds);	//添加值vector
			break;
		  }
		  case 2: {		//二维数组
			vector<vector<bytes>> dss;
			int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();	//一维数组数目
			int numSubElem = td.dimensions[1] ? td.dimensions[1] : consultRealLen();	//一维数组元素个数
			for (int i = 0; i < numElem; i += 1) {	//遍历每个一维数组
			  vector<bytes> ds;
			  for (int j = 0; j < numSubElem; j += 1) {	//遍历每个数组元素
				//确定动态元素个数及比特数
				int realLen = td.isDynamic ? consultRealLen() : 32;
				int containerLen = consultContainerLen(realLen);
				padLen(containerLen);	//填充数据
				bytes d(data.begin() + offset, data.begin() + offset + realLen);
				ds.push_back(d);	//添加
                offset += containerLen;  //偏移指针后移
			  }
			  dss.push_back(ds);
			  /* If address, extract account */
              //若参数为地址则提取到账户
			  if (boost::starts_with(td.name, "address")) {
				accounts.insert(accounts.end(), ds.begin(), ds.end());
			  }
			}
			td.addValue(dss);	//添加值
			break;
		  }
		}
	  }
	}
  }

  void ContractABI::updateDynamicIdx() {
      FILE* fp;
      string filename = "./testcases/" + contractName + "/dynamicIdx.dat";
      if ((fp = fopen(filename.c_str(), "r")) == nullptr){
          return;
      }
      unsigned char dyIdxSize;
      unsigned char buf[160];
      fread(&dyIdxSize,1,sizeof(unsigned char),fp);
      fread(buf, dyIdxSize, 1, fp);
      dynamicIdx = bytes(buf, buf + dyIdxSize);
      fclose(fp);
  }

  void ContractABI::updateTestcaseCnt() {
      FILE* fp;
      string filename = "./testcases/" + contractName + "/testcaseCnt.dat";
      if ((fp = fopen(filename.c_str(), "r")) == nullptr)
          return;
      fread(&testcaseCnt,1,sizeof(unsigned char),fp);
      fclose(fp);
  }

  bytes ContractABI::initTestcase() {
      FILE* fp;
      string filename = "./testcases/" + contractName + "/testcase"
                        + to_string(++testcaseIdx) + ".dat";
	  if ((fp = fopen(filename.c_str(), "r")) == nullptr) {
          return randomTestcase();
	  }

      const unsigned bufSize = 160, argSize = 32;
      unsigned char buf[bufSize];
//      auto opttestcase=[](bytes ret){
//        auto idx = 0;
//        stringstream ss;
//        while (idx < ret.size()) {
//            bytes d(ret.begin() + idx, ret.begin() + idx + 32);
//            idx += 32;
//            ss << toHex(d) << endl;
//        }
//        return ss.str();
//      };

      bytes ret;
      auto readSize = fread(buf, 1, argSize, fp);
	  while (readSize==argSize) {
          ret.insert(ret.end(), buf, buf + argSize);
          readSize = fread(buf, 1, argSize, fp);
	  }
	  fclose(fp);
      return ret;
  }

  //为模糊测试初始化测试用例		chg
  bytes ContractABI::randomTestcase() {
	/*
	 * Random value for ABI
	 * | --- dynamic len (32 bytes) -- | sender | blockNumber(8) + timestamp(8) | content |
	 */
	//前96字节为初始配置
    //dynamicIdx = bytes(32, 5);	//chg
	//bytes ret(32, 5);	//返回的测试用例, 先初始化32个5表示动态长度设置
    bool hasDynamicIdx = dynamicIdx.size();
    bytes ret;
	int lenOffset = 0;	//动态长度偏移量(用于设定动态参数类型的元素数)
	//lambda: 从动态查询参数真正长度(元素个数)
	auto consultRealLen = [&]() {
	  //int len = ret[lenOffset];	
	  //lenOffset = (lenOffset + 1) % 32;
	  if (hasDynamicIdx) {
          return dynamicIdx[lenOffset++];
	  }
      dynamicIdx.push_back(5);
      return byte(5);
	  //return len;	//返回可变参数类型的长度(元素个数)
	};
	//lambda:查询整个数组的长度(bit)
	auto consultContainerLen = [](int realLen) {
	  //realLen在数组时表示元素个数, 单个元素时表示32bit
	  if (!(realLen % 32)) return realLen;	//单个元素直接返回32bit
	  return (realLen / 32 + 1) * 32;	//数组元素返回 元素个数*32bit
	};
	/* sender env */
	bytes sender(32, 0);	//sender is balance + address
	bytes block(32, 0);		//blocknumber + timestamp
	ret.insert(ret.end(), sender.begin(), sender.end());
	ret.insert(ret.end(), block.begin(), block.end());
	for (auto fd : this->fds) {		//遍历每个函数
	  for (auto td : fd.tds) {	//遍历每个参数
		//根据位数添加参数值(初始值全为0)
		switch(td.dimensions.size()) {	//判断维数
		  case 0: {		//单个元素
			//设定参数的动态长度, 静态为32(推测为bit)
			int realLen = td.isDynamic ? consultRealLen() : 32;
			//容器长度即数组长度
			int containerLen = consultContainerLen(realLen);	
			bytes data(containerLen, 0);
			ret.insert(ret.end(), data.begin(), data.end());	//插入参数值
			break;
		  }
		  case 1: {
			//根据是否为动态数组设定元素数
			int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();	
			for (int i = 0; i < numElem; i += 1) {
			  int realLen = td.isDynamic ? consultRealLen() : 32;
			  int containerLen = consultContainerLen(realLen);
			  bytes data = bytes(containerLen, 0);
			  ret.insert(ret.end(), data.begin(), data.end());
			}
			break;
		  }
		  case 2: {
			int numElem = td.dimensions[0] ? td.dimensions[0] : consultRealLen();
			//子数组设定元素个数
			int numSubElem = td.dimensions[1] ? td.dimensions[1] : consultRealLen();
			for (int i = 0; i < numElem; i += 1) {
			  for (int j = 0; j < numSubElem; j += 1) {
				int realLen = td.isDynamic ? consultRealLen() : 32;
				int containerLen = consultContainerLen(realLen);
				bytes data = bytes(containerLen, 0);
				ret.insert(ret.end(), data.begin(), data.end());
			  }
			}
			break;
		  }
		}
	  }
	}
	return ret;
  }

  //合约ABI初始化
  ContractABI::ContractABI(string abiJson, string name) {
	stringstream ss;
	ss << abiJson;
	pt::ptree root;
	pt::read_json(ss, root);
	for (auto node : root) {
	  vector<TypeDef> tds;	//函数入口参数vector
	  string type = node.second.get<string>("type");
	  string constant = "false";
	  bool payable = false;
	  //常量函数
	  if (node.second.get_child_optional("constant")) {	//get_child_optional用于判断当前节点是否存在
		constant = node.second.get<string>("constant");
	  }
	  //回退函数是可交易的
	  if (type == "fallback") {
		if (node.second.get_child_optional("payable")) {
		  payable = node.second.get<bool>("payable");
		}
		this->fds.push_back(FuncDef("fallback", tds, payable));		//添加回退函数
	  }
	  //构造函数或非常量普通函数
	  if ((type == "constructor" || type == "function") && constant == "false") {
		auto inputNodes = node.second.get_child("inputs");	//函数输入
		string name = type == "constructor" ? "" : node.second.get<string>("name");	//函数名
		if (node.second.get_child_optional("payable")) {
		  payable = node.second.get<bool>("payable");	//是否可交易
		}
		for (auto inputNode : inputNodes) {
		  string type = inputNode.second.get<string>("type");
		  tds.push_back(TypeDef(type));	//添加入口参数
		}
		this->fds.push_back(FuncDef(name, tds, payable));	//添加函数
	  }
	};

    //chg
    contractName = name.substr(name.find_last_of(':')+1);
    updateDynamicIdx();

  }

  //编码构造函数
  bytes ContractABI::encodeConstructor() {
    //寻找构造函数
	auto it = find_if(fds.begin(), fds.end(), [](FuncDef fd) { return fd.name == "";});
	if (it != fds.end()) return encodeTuple((*it).tds);	//有构造函数则进行编码
	return bytes(0, 0);
  }

  //返回合约函数是否是可交易的
  bool ContractABI::isPayable(string name) {
	for (auto fd : fds) {
	  if (fd.name == name) return fd.payable;
	}
	return false;
  }

  //对函数进行编码: 函数选择器+函数参数列表数据值
  vector<bytes> ContractABI::encodeFunctions() {
	vector<bytes> ret;
	for (auto fd : fds) {	//遍历函数
	  if (fd.name != "") {
		//函数选择器
		bytes selector = functionSelector(fd.name /* name */, fd.tds /* type defs */);
		bytes data = encodeTuple(fd.tds);	//编码的数据
		selector.insert(selector.end(), data.begin(), data.end());
		ret.push_back(selector);
	  }
	}
	return ret;
  }

  //对函数构造函数选择器
  bytes ContractABI::functionSelector(string name, vector<TypeDef> tds) {
	vector<string> argTypes;
	//将参数vector中所有参数的类型名均置入argTypes中
	transform(tds.begin(), tds.end(), back_inserter(argTypes), [](TypeDef td) {
	  return td.fullname;
	});
	//transform:将某操作应用于指定范围的每个元素
	//构造函数签名
	string signature = name + "(" + boost::algorithm::join(argTypes, ",") + ")";
	//对函数签名hash
	bytes fullSelector = sha3(signature).ref().toBytes();
	return bytes(fullSelector.begin(), fullSelector.begin() + 4);	//前4个字节构成函数选择器
  }

  //对参数列表编码
  bytes ContractABI::encodeTuple(vector<TypeDef> tds) {
	bytes ret;
	/* Payload */
	bytes payload;
	vector<int> dataOffset = {0};
	//动态参数处理
	for (auto td : tds) {	//遍历所有参数
	  //若为动态参数
	  if (td.isDynamic || td.isDynamicArray || td.isSubDynamicArray) {
		bytes data;
		switch (td.dimensions.size()) {	//判断维度
		  case 0: {	//单个变量
			data = encodeSingle(td.dt);
			break;
		  }
		  case 1: {	//一维数组
			data = encodeArray(td.dts, td.isDynamicArray);
			break;
		  }
		  case 2: {	//二维数组
			data = encode2DArray(td.dtss, td.isDynamicArray, td.isSubDynamicArray);
			break;
		  }
		}
		dataOffset.push_back(dataOffset.back() + data.size());
		payload.insert(payload.end(), data.begin(), data.end());
	  }
	}
	/* Calculate offset */
	//计算偏移量
	u256 headerOffset = 0;
	for (auto td : tds) {	//遍历所有参数
	  //动态参数
	  if (td.isDynamic || td.isDynamicArray || td.isSubDynamicArray) {
		headerOffset += 32;
	  } else {	//非动态参数
		switch (td.dimensions.size()) {
		  case 0: {
			headerOffset += encodeSingle(td.dt).size();
			break;
		  }
		  case 1: {
			headerOffset += encodeArray(td.dts, td.isDynamicArray).size();
			break;
		  }
		  case 2: {
			headerOffset += encode2DArray(td.dtss, td.isDynamicArray, td.isSubDynamicArray).size();
			break;
		  }
		}
	  }
	}
	//长度头信息
	bytes header;
	int dynamicCount = 0;
	for (auto td : tds) {	//遍历每个参数
	  /* Dynamic in head */
	  //动态参数
	  if (td.isDynamic || td.isDynamicArray || td.isSubDynamicArray) {
		u256 offset = headerOffset + dataOffset[dynamicCount];
		/* Convert to byte */
		for (int i = 0; i < 32; i += 1) {
		  byte b = (byte) (offset >> ((32 - i - 1) * 8)) & 0xFF;
		  header.push_back(b);
		}
		dynamicCount ++;
	  } else {	//静态参数
		/* static in head */
		bytes data;
		switch (td.dimensions.size()) {
		  case 0: {
			data = encodeSingle(td.dt);
			break;
		  }
		  case 1: {
			data = encodeArray(td.dts, td.isDynamicArray);
			break;
		  }
		  case 2: {
			data = encode2DArray(td.dtss, td.isDynamicArray, td.isSubDynamicArray);
			break;
		  }
		}
		header.insert(header.end(), data.begin(), data.end());
	  }
	}
	/* Head + Payload */
	ret.insert(ret.end(), header.begin(), header.end());
	ret.insert(ret.end(), payload.begin(), payload.end());
	return ret;
  }

  //二维数组数据编码
  bytes ContractABI::encode2DArray(vector<vector<DataType>> dtss, bool isDynamicArray, bool isSubDynamic) {
	bytes ret;
	//是动态二维数组
	if (isDynamicArray) {
	  bytes payload;
	  bytes header;
	  u256 numElem = dtss.size();
	  //子数组是动态一维数组
	  if (isSubDynamic) {
		/* Need Offset*/
		vector<int> dataOffset = {0};
		//编码每个子数组
		for (auto dts : dtss) {
		  bytes data = encodeArray(dts, isSubDynamic);
		  dataOffset.push_back(dataOffset.back() + data.size());
		  payload.insert(payload.end(), data.begin(), data.end());
		}
		/* Count */
		//二维数组长度头信息
		for (int i = 0; i < 32; i += 1) {
		  byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
		  header.push_back(b);
		}
		//每个一维子数组的长度头信息
		for (int i = 0; i < numElem; i += 1) {
		  u256 headerOffset =  32 * numElem + dataOffset[i];
		  for (int i = 0; i < 32; i += 1) {
			byte b = (byte) (headerOffset >> ((32 - i - 1) * 8)) & 0xFF;
			header.push_back(b);
		  }
		}
	  }
	  //子数组非动态一维数组
	  else {
		/* Count */
		//二维数组长度头信息
		for (int i = 0; i < 32; i += 1) {
		  byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
		  header.push_back(b);
		}
		//编码每个子数组
		for (auto dts : dtss) {
		  bytes data = encodeArray(dts, isSubDynamic);
		  payload.insert(payload.end(), data.begin(), data.end());
		}
	  }
	  ret.insert(ret.end(), header.begin(), header.end());
	  ret.insert(ret.end(), payload.begin(), payload.end());
	  return ret;
	}
	//非动态二维数组
	for (auto dts : dtss) {	//编码每个子数组
	  bytes data = encodeArray(dts, isSubDynamic);
	  ret.insert(ret.end(), data.begin(), data.end());
	}
	return ret;
  }

  //一维数组数据编码
  bytes ContractABI::encodeArray(vector<DataType> dts, bool isDynamicArray) {
	bytes ret;
	/* T[] */
	//是动态一位数组
	if (isDynamicArray) {
	  /* Calculate header and payload */
	  bytes payload;
	  bytes header;
	  u256 numElem = dts.size();	//元素个数
	  //元素是动态元素
	  if (dts[0].isDynamic) {
		/* If element is dynamic then needs offset */
		vector<int> dataOffset = {0};
		for (auto dt : dts) {	//遍历每个元素
		  bytes data = encodeSingle(dt);	//编码每个元素
		  dataOffset.push_back(dataOffset.back() + data.size());	//每个动态元素的偏移指针
		  payload.insert(payload.end(), data.begin(), data.end());
		}
		/* Count */
		//数组长度头信息
		for (int i = 0; i < 32; i += 1) {
		  byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
		  header.push_back(b);
		}
		/* Offset */
		//每个元素的长度头信息
		for (int i = 0; i < numElem; i += 1) {
		  u256 headerOffset =  32 * numElem + dataOffset[i];
		  for (int i = 0; i < 32; i += 1) {
			byte b = (byte) (headerOffset >> ((32 - i - 1) * 8)) & 0xFF;
			header.push_back(b);
		  }
		}
	  }
	  //元素非动态
	  else {
		/* Do not need offset, count them */
		//数组长度头信息
		for (int i = 0; i < 32; i += 1) {
		  byte b = (byte) (numElem >> ((32 - i - 1) * 8)) & 0xFF;
		  header.push_back(b);
		}
		//每个元素编码
		for (auto dt : dts) {
		  bytes data = encodeSingle(dt);
		  payload.insert(payload.end(), data.begin(), data.end());
		}
	  }
	  ret.insert(ret.end(), header.begin(), header.end());
	  ret.insert(ret.end(), payload.begin(), payload.end());
	  return ret;
	}
	/* T[k] */
	//是非动态一维数组
	for (auto dt : dts) {	//遍历每个元素编码
	  bytes data = encodeSingle(dt);
	  ret.insert(ret.end(), data.begin(), data.end());
	}
	return ret;
  }

  //单个参数数据编码
  bytes ContractABI::encodeSingle(DataType dt) {
	bytes ret;
	bytes payload = dt.payload();	//填充后的数据
    //是动态数据
	if (dt.isDynamic) {	
	  /* Concat len and data */
	  bytes header = dt.header();	//动态数据要添加长度头信息
	  ret.insert(ret.end(), header.begin(), header.end());	//添加头
	  ret.insert(ret.end(), payload.begin(), payload.end());	//添加数据
	  return ret;
	}
	//是非动态数据
	ret.insert(ret.end(), payload.begin(), payload.end());	//添加数据
	return ret;
  }

  //数据初始化
  DataType::DataType(bytes value, bool padLeft, bool isDynamic) {
	this->value = value;
	this->padLeft = padLeft;
	this->isDynamic = isDynamic;
  }

  //返回以bytes表示的数据长度
  bytes DataType::header() {
	u256 size = this->value.size();	//数据长
	bytes ret;
	for (int i = 0; i < 32; i += 1) {
	  byte b = (byte) (size >> ((32 - i - 1) * 8)) & 0xFF;
	  ret.push_back(b);
	}
	return ret;
  }

  //数据负载:对数据进行填充
  bytes DataType::payload() {
	//lambda:左填充:0+数据值
	auto paddingLeft = [this](double toLen) {
	  bytes ret(toLen - this->value.size(), 0);
	  ret.insert(ret.end(), this->value.begin(), this->value.end());
	  return ret;
	};
	//lambda:右填充:数据值+0
	auto paddingRight = [this](double toLen) {
	  bytes ret;
	  ret.insert(ret.end(), this->value.begin(), this->value.end());
	  while(ret.size() < toLen) ret.push_back(0);
	  return ret;
	};
	if (this->value.size() > 32) {	//若值的大小大于32
	  if (!this->isDynamic) throw "Size of static <= 32 bytes";	//不是动态数据则抛出异常
	  int valueSize = this->value.size();	//值大小
	  //填充
	  int finalSize = valueSize % 32 == 0 ? valueSize : (valueSize / 32 + 1) * 32;
	  if (this->padLeft) return paddingLeft(finalSize);
	  return paddingRight(finalSize);
	}
	//一般变量直接填充32大小
	if (this->padLeft) return paddingLeft(32);
	return paddingRight(32);
  }

  //转换为实际类型(address -> unit160..)
  string TypeDef::toRealname(string name) {
	string fullType = toFullname(name);
	string searchPatterns[2] = {"address[", "bool["};
	string replaceCandidates[2] = {"uint160", "uint8"};
	for (int i = 0; i < 2; i += 1) {
	  string pattern = searchPatterns[i];
	  string candidate = replaceCandidates[i];
	  if (boost::starts_with(fullType, pattern))
		return candidate + fullType.substr(pattern.length() - 1);
	  if (fullType == pattern.substr(0, pattern.length() - 1)) return candidate;
	}
	return fullType;
  }

  //转换为参数类型全名(int -> int256...)
  string TypeDef::toFullname(string name) {
	string searchPatterns[4] = {"int[", "uint[", "fixed[", "ufixed["};
	string replaceCandidates[4] = {"int256", "uint256", "fixed128x128", "ufixed128x128"};
	for (int i = 0; i < 4; i += 1) {
	  string pattern = searchPatterns[i];
	  string candidate = replaceCandidates[i];
	  if (boost::starts_with(name, pattern))
		return candidate + name.substr(pattern.length() - 1);
	  if (name == pattern.substr(0, pattern.length() - 1)) return candidate;
	}
	return name;
  }

  //提取参数类型维度: 数组的每一维的元素个数, 动态数组个数定为0
  vector<int> TypeDef::extractDimension(string name) {
	vector<int> ret;
	smatch sm;
	regex_match(name, sm, regex("[a-z]+[0-9]*\\[(\\d*)\\]\\[(\\d*)\\]"));
	if (sm.size() == 3) {
	  /* Two dimension array */
	  //2维数组
	  ret.push_back(sm[1] == "" ? 0 : stoi(sm[1]));
	  ret.push_back(sm[2] == "" ? 0 : stoi(sm[2]));
	  return ret;
	}
	regex_match(name, sm, regex("[a-z]+[0-9]*\\[(\\d*)\\]"));
	if (sm.size() == 2) {
	  /* One dimension array */
	  //1维数组
	  ret.push_back(sm[1] == "" ? 0 : stoi(sm[1]));
	  return ret;
	}
	return ret;
  }

  //添加二维数组参数数据值
  void TypeDef::addValue(vector<vector<bytes>> vss) {
	if (this->dimensions.size() != 2) throw "Invalid dimension";;
	for (auto vs : vss) {
	  vector<DataType> dts;
	  for (auto v : vs) {
		dts.push_back(DataType(v, this->padLeft, this->isDynamic));
	  }
	  this->dtss.push_back(dts);
	}
  }

  //添加一维数组参数数据值
  void TypeDef::addValue(vector<bytes> vs) {
	if (this->dimensions.size() != 1) throw "Invalid dimension";
	for (auto v : vs) {
	  this->dts.push_back(DataType(v, this->padLeft, this->isDynamic));
	}
  }

  //添加单个变量参数数据值
  void TypeDef::addValue(bytes v) {
	if (this->dimensions.size()) throw "Invalid dimension";
	this->dt = DataType(v, this->padLeft, this->isDynamic);
  }
  
  TypeDef::TypeDef(string name) {
	this->name = name;	//参数名
	this->fullname = toFullname(name);	//参数全名
	this->realname = toRealname(name);	//参数真名
	this->dimensions = extractDimension(name);	//参数维度
	this->padLeft = !boost::starts_with(this->fullname, "bytes") && !boost::starts_with(this->fullname, "string");
	int numDimension = this->dimensions.size();	//维度
	if (!numDimension) {	//单个变量
	  this->isDynamic = this->fullname == "string" || this->name == "bytes";
	  this->isDynamicArray = false;
	  this->isSubDynamicArray = false;
	} else if (numDimension == 1) {		//一维数组
	  this->isDynamic = boost::starts_with(this->fullname, "string[")
	  || boost::starts_with(this->fullname, "bytes[");
	  this->isDynamicArray = this->dimensions[0] == 0;
	  this->isSubDynamicArray = false;
	} else {	//二维数组
	  this->isDynamic = boost::starts_with(this->fullname, "string[")
	  || boost::starts_with(this->fullname, "bytes[");
	  this->isDynamicArray = this->dimensions[0] == 0;
	  this->isSubDynamicArray = this->dimensions[1] == 0;
	}
  }
}
