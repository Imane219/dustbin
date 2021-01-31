#include "TargetExecutive.h"
#include "Logger.h"

namespace fuzzer {
  //部署合约
  void TargetExecutive::deploy(bytes data, OnOpFunc onOp) {
    ca.updateTestData(data);
    program->deploy(addr, bytes{code});
    program->setBalance(addr, DEFAULT_BALANCE);		//合约余额
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);	//调用构造函数
  }

  //执行合约
  TargetContainerResult TargetExecutive::exec(bytes data, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>>& validJumpis) {
    /* Save all hit branches to trace_bits */
	//将所有命中分支保存到trace_bits
    Instruction prevInst;	//先前指令
    RecordParam recordParam;	//记录参数
    u256 lastCompValue = 0;	//上次比较值(差值)
	//分支的两个jumpdest
    u64 jumpDest1 = 0;
    u64 jumpDest2 = 0;
    unordered_set<string> uniqExceptions;	//执行出现异常的pc的集合
    unordered_set<string> tracebits;	//覆盖到的分支ID(lastpc:pc=jump-pc:jumpdest-pc)集合
    unordered_map<string, u256> predicates;	//hashmap: 发现但未覆盖的 分支ID-distance值
    vector<bytes> outputs;	//存储合约函数调用后输出
    size_t savepoint = program->savepoint();	//设置目标程序保存点
	//处理opcode指令函数
    OnOpFunc onOp = [&](u64, u64 pc, Instruction inst, bigint, bigint, bigint, VMFace const* _vm, ExtVMFace const* ext) {
      auto vm = dynamic_cast<LegacyVM const*>(_vm);	//以太坊虚拟机
      /* Oracle analyze data */
      switch (inst) {
		//CALL相关指令
        case Instruction::CALL:
        case Instruction::CALLCODE:
        case Instruction::DELEGATECALL:
        case Instruction::STATICCALL: {
          vector<u256>::size_type stackSize = vm->stack().size();	//栈大小
          u256 wei = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? vm->stack()[stackSize - 3] : 0;		//传递的交易值
          auto sizeOffset = (inst == Instruction::CALL || inst == Instruction::CALLCODE) ? (stackSize - 4) : (stackSize - 3);	//偏移值
          auto inOff = (uint64_t) vm->stack()[sizeOffset];	//内存的起点
          auto inSize = (uint64_t) vm->stack()[sizeOffset - 1];	//数据的长度
          auto first = vm->memory().begin();
		  //设置opcode属性
		  OpcodePayload payload;
          payload.caller = ext->myAddress;
          payload.callee = Address((u160)vm->stack()[stackSize - 2]);
          payload.pc = pc;
          payload.gas = vm->stack()[stackSize - 1];
          payload.wei = wei;
          payload.inst = inst;
          payload.data = bytes(first + inOff, first + inOff + inSize);	//call的数据(字节码)
          oracleFactory->save(OpcodeContext(ext->depth + 1, payload));	//将信息保存
          break;
        }
        default: {
          OpcodePayload payload;
          payload.pc = pc;
          payload.inst = inst;
          if (
              inst == Instruction::SUICIDE ||
              inst == Instruction::NUMBER ||
              inst == Instruction::TIMESTAMP ||
              inst == Instruction::INVALID ||
              inst == Instruction::ADD ||
              inst == Instruction::SUB
              ) {
            vector<u256>::size_type stackSize = vm->stack().size();
			//判断是否有整数溢出, 并标定isOverflow/isUnderflow
            if (inst == Instruction::ADD || inst == Instruction::SUB) {
              auto left = vm->stack()[stackSize - 1];	//指令左边的数
              auto right = vm->stack()[stackSize - 2];	//右边的数
              if (inst == Instruction::ADD) {
                auto total256 = left + right;
                auto total512 = (u512) left + (u512) right;
                payload.isOverflow = total512 != total256;	//判断是否溢出
              }
              if (inst == Instruction::SUB) {
                payload.isUnderflow = left < right;
              }
            }
            oracleFactory->save(OpcodeContext(ext->depth + 1, payload));	//将信息保存
          }
          break;
        }
      }
      /* Mutation analyzes data */
	  //突变分析数据
      switch (inst) {
		//与比较有关的指令
        case Instruction::GT:
        case Instruction::SGT:
        case Instruction::LT:
        case Instruction::SLT:
        case Instruction::EQ: {
          vector<u256>::size_type stackSize = vm->stack().size();
          if (stackSize >= 2) {
            u256 left = vm->stack()[stackSize - 1];
            u256 right = vm->stack()[stackSize - 2];
            /* calculate if command inside a function */
			//计算命令中是否有函数
			//两数差值
            u256 temp = left > right ? left - right : right - left;
            lastCompValue = temp + 1;	//差值+1用于作备选distance值
          }
          break;
        }
        default: { break; }
      }
      /* Calculate left and right branches for valid jumpis*/
	  //计算有效跳转的左右分支
      auto recordable = recordParam.isDeployment && get<0>(validJumpis).count(pc);	//合约部署部分且在有效的jumpi中
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(pc);	//合约运行时部分且在有效的jumpi中
      if (inst == Instruction::JUMPCI && recordable) {
        jumpDest1 = (u64) vm->stack().back();	//栈中最后一个元素 pc的值
        jumpDest2 = pc + 1;	//pc下一个值
      }
      /* Calculate actual jumpdest and add reverse branch to predicate */
	  //计算实际的Jumpdest并添加反向分支作为谓词
      recordable = recordParam.isDeployment && get<0>(validJumpis).count(recordParam.lastpc);	//合约部署部分且lastpc在有效的jumpi中
      recordable = recordable || !recordParam.isDeployment && get<1>(validJumpis).count(recordParam.lastpc);	//合约运行时部分且lastpc在有效的jumpi中
      if (prevInst == Instruction::JUMPCI && recordable) {
        auto branchId = to_string(recordParam.lastpc) + ":" + to_string(pc);	//分支号: jump-pc和本次jumpdest-pc
        tracebits.insert(branchId);		//将分支号添加到跟踪位中
        /* Calculate branch distance */
		//计算分支距离
		//未到达的分支的jumpDest: 若pc==jumpDest1,则目的地jumpDest为jumpDest2, 反之为jumpDest1
        u64 jumpDest = pc == jumpDest1 ? jumpDest2 : jumpDest1;	
        branchId = to_string(recordParam.lastpc) + ":" + to_string(jumpDest);	//未到达分支的分支号
        predicates[branchId] = lastCompValue;	//存储distance值
      }
      prevInst = inst;	//记当前指令为上一指令
      recordParam.lastpc = pc;	//pc为上一pc
    };	//lambda-onOp

    /* Decode and call functions */
	//解码并调用函数
    ca.updateTestData(data);
    vector<bytes> funcs = ca.encodeFunctions();	//合约函数编码后数据
	//交易设置
    program->deploy(addr, code);
    program->setBalance(addr, DEFAULT_BALANCE);		//设置合约账户余额
    program->updateEnv(ca.decodeAccounts(), ca.decodeBlock());
    oracleFactory->initialize();	//初始化测试预言工厂
    /* Record all JUMPI in constructor */
    recordParam.isDeployment = true;	//部署部分代码
    auto sender = ca.getSender();	//发送者地址
	//设置opcode属性
	OpcodePayload payload;
    payload.inst = Instruction::CALL;
    payload.data = ca.encodeConstructor();
    payload.wei = ca.isPayable("") ? program->getBalance(sender) / 2 : 0;	//交易金额
    payload.caller = sender;	//发送方是攻击合约
    payload.callee = addr;		//接收方(开始时攻击合约后来是测试合约)
    oracleFactory->save(OpcodeContext(0, payload));
	//调用合约构造函数
    auto res = program->invoke(addr, CONTRACT_CONSTRUCTOR, ca.encodeConstructor(), ca.isPayable(""), onOp);
    //若出现交易异常
	if (res.excepted != TransactionException::None) {
      auto exceptionId = to_string(recordParam.lastpc);
      uniqExceptions.insert(exceptionId);	//记录异常的pc值
      /* Save Call Log */
      OpcodePayload payload;
      payload.inst = Instruction::INVALID;
      oracleFactory->save(OpcodeContext(0, payload));	//存储opcode
    }
    oracleFactory->finalize();
    for (uint32_t funcIdx = 0; funcIdx < funcs.size(); funcIdx ++ ) {	//遍历每个合约函数
      /* Update payload */
      auto func = funcs[funcIdx];	//函数编码后数据
      auto fd = ca.fds[funcIdx];	//函数定义
      /* Ignore JUMPI until program reaches inside function */
	  //忽略jumpi知道进入到了函数内部
	  //设置opcode
      recordParam.isDeployment = false;		//第一个jumpi是合约的函数表路由, 运行时部分
      OpcodePayload payload;
      payload.data = func;
      payload.inst = Instruction::CALL;
      payload.wei = ca.isPayable(fd.name) ? program->getBalance(sender) / 2 : 0;
      payload.caller = sender;
      payload.callee = addr;
      oracleFactory->save(OpcodeContext(0, payload));
	  //调用合约函数
      res = program->invoke(addr, CONTRACT_FUNCTION, func, ca.isPayable(fd.name), onOp);
      outputs.push_back(res.output);
	  //若出现交易异常
      if (res.excepted != TransactionException::None) {
        auto exceptionId = to_string(recordParam.lastpc);
        uniqExceptions.insert(exceptionId);
        /* Save Call Log */
        OpcodePayload payload;
        payload.inst = Instruction::INVALID;
        oracleFactory->save(OpcodeContext(0, payload));
      }
      oracleFactory->finalize();
    }
    /* Reset data before running new contract */
    program->rollback(savepoint);	//状态回滚
    string cksum = "";
    for (auto t : tracebits) cksum = cksum + t;		//合约中记录的全部覆盖分支ID
    return TargetContainerResult(tracebits, predicates, uniqExceptions, cksum);
  }
}
