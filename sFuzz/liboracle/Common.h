#pragma once
#include <iostream>
#include <libdevcore/CommonIO.h>
#include <libevm/LegacyVM.h>

using namespace dev;
using namespace eth;
using namespace std;

const uint8_t GASLESS_SEND = 0;
const uint8_t EXCEPTION_DISORDER = 1;
const uint8_t TIME_DEPENDENCY = 2;
const uint8_t NUMBER_DEPENDENCY = 3;
const uint8_t DELEGATE_CALL = 4;
const uint8_t REENTRANCY = 5;
const uint8_t FREEZING = 6;
const uint8_t OVERFLOW = 7;
const uint8_t UNDERFLOW = 8;

//字节码负载(交易属性)
struct OpcodePayload {
  u256 wei = 0;		//交易金额
  u256 gas = 0;		//交易的gas
  u256 pc = 0;
  Instruction inst;
  bytes data;
  Address caller;
  Address callee;
  bool isOverflow = false;
  bool isUnderflow = false;
};

//opcode语境
struct OpcodeContext {
  u256 level;
  OpcodePayload payload;	//opcode属性
  OpcodeContext(u256 _level, OpcodePayload _payload): level(_level), payload(_payload) {}
};

using SingleFunction = vector<OpcodeContext>;
using MultipleFunction = vector<SingleFunction>;
