#include "OracleFactory.h"

using namespace dev;
using namespace eth;
using namespace std;

//测试预言工厂初始化
void OracleFactory::initialize() {
  function.clear();
}

//预言工厂结束
void OracleFactory::finalize() {
  functions.push_back(function);
  function.clear();
}

//存储opcode语句
void OracleFactory::save(OpcodeContext ctx) {
  function.push_back(ctx);
}

//根据测试预言进行漏洞分析
vector<bool> OracleFactory::analyze() {
  uint8_t total = 9;	//共9种漏洞
  //初始化漏洞数组区分false
  while (vulnerabilities.size() < total) {
    vulnerabilities.push_back(false);
  }
  for (auto function : functions) {  //遍历每个函数
    for (uint8_t i = 0; i < total; i ++) {	//遍历每种漏洞
      if (!vulnerabilities[i]) {	//漏洞分析(若之前该漏洞未发现)
        switch (i) {
		  //无气发送
          case GASLESS_SEND: {
            for (auto ctx: function) {
              auto level = ctx.level;
              auto inst = ctx.payload.inst;
              auto gas = ctx.payload.gas;
              auto data = ctx.payload.data;
              vulnerabilities[i] = vulnerabilities[i] || (level == 1 && inst == Instruction::CALL && !data.size() && (gas == 2300 || gas == 0));
            }
            break;
          }
		  //异常混乱
          case EXCEPTION_DISORDER: {
            auto rootCallResponse = function[function.size() - 1];
            bool rootException = rootCallResponse.payload.inst == Instruction::INVALID && !rootCallResponse.level;
            for (auto ctx : function) {
              vulnerabilities[i] = vulnerabilities[i] || (!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level);
            }
            break;
          }
		  //时间戳依赖
          case TIME_DEPENDENCY: {
            auto has_transfer = false;
            auto has_timestamp = false;
            for (auto ctx : function) {
              has_transfer = has_transfer || ctx.payload.wei > 0;
              has_timestamp = has_timestamp || ctx.payload.inst == Instruction::TIMESTAMP;
            }
            vulnerabilities[i] = has_transfer && has_timestamp;
            break;
          }
		  //区块号依赖
          case NUMBER_DEPENDENCY: {
            auto has_transfer = false;
            auto has_number = false;
            for (auto ctx : function) {
              has_transfer = has_transfer || ctx.payload.wei > 0;
              has_number = has_number || ctx.payload.inst == Instruction::NUMBER;
            }
            vulnerabilities[i] = has_transfer && has_number;
            break;
          }
		  //Delegatecall
          case DELEGATE_CALL: {
            auto rootCall = function[0];
            auto data = rootCall.payload.data;
            auto caller = rootCall.payload.caller;
            for (auto ctx : function) {
              if (ctx.payload.inst == Instruction::DELEGATECALL) {
                vulnerabilities[i] = vulnerabilities[i]
                    || data == ctx.payload.data
                    || caller == ctx.payload.callee
                    || toHex(data).find(toHex(ctx.payload.callee)) != string::npos;
              }
            }
            break;
          }
		  //重入漏洞
          case REENTRANCY: {
            auto has_loop = false;
            auto has_transfer = false;
            for (auto ctx : function) {
              has_loop = has_loop || (ctx.level >= 4 &&  toHex(ctx.payload.data) == "000000ff");
              has_transfer = has_transfer || ctx.payload.wei > 0;
            }
            vulnerabilities[i] = has_loop && has_transfer;
            break;
          }
		  //冻结以太币
          case FREEZING: {
            auto has_delegate = false;
            auto has_transfer = false;
            for (auto ctx: function) {
              has_delegate = has_delegate || ctx.payload.inst == Instruction::DELEGATECALL;
              has_transfer = has_transfer || (ctx.level == 1 && (
                   ctx.payload.inst == Instruction::CALL
                || ctx.payload.inst == Instruction::CALLCODE
                || ctx.payload.inst == Instruction::SUICIDE
              ));
            }
            vulnerabilities[i] = has_delegate && !has_transfer;
            break;
          }
		  //下溢
          case UNDERFLOW: {
            for (auto ctx: function) {
              vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isUnderflow;
            }
            break;
          }
		  //上溢
          case OVERFLOW: {
            for (auto ctx: function) {
              vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isOverflow;
            }
            break;
          }
        }
      }
    }
  }
  functions.clear();	//清空函数
  return vulnerabilities;
}
