/*
	This file is part of cpp-ethereum.

	cpp-ethereum is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	cpp-ethereum is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file VM.h
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#pragma once

#include <unordered_map>
#include <libdevcore/Exceptions.h>
#include <libethcore/Common.h>
#include <libevmcore/Instruction.h>
#include <libdevcore/SHA3.h>
#include <libethcore/BlockHeader.h>
#include "VMFace.h"

namespace dev
{
namespace eth
{

// Convert from a 256-bit integer stack/memory entry into a 160-bit Address hash.
// Currently we just pull out the right (low-order in BE) 160-bits.
inline Address asAddress(u256 _item)
{
	return right160(h256(_item));
}

inline u256 fromAddress(Address _a)
{
	return (u160)_a;
}


struct InstructionMetric
{
	int gasPriceTier;
	int args;
	int ret;
};

// real machine word, virtual machine word, signed and unsigned overflow words
typedef uint64_t mw64;
typedef mw64 rmword;
typedef u256 vmword;
typedef s512 soword;
typedef u512 uoword;


/**
 */
class VM: public VMFace
{
public:
	virtual bytesConstRef execImpl(u256& io_gas, ExtVMFace& _ext, OnOpFunc const& _onOp) override final;

	bytes const& memory() const { return m_mem; }
	u256s stack() const { assert(m_stack <= *m_pSP+1); return u256s(m_stack, *m_pSP+1); };
	
	VM(): m_stack_vector(1025), m_stack(m_stack_vector.data()+1) {};

private:

	struct InnerState
	{
		InnerState(byte* p=0, unsigned n=0, Instruction i=Instruction::STOP, uint64_t pc=0, u256* sp=0)
			: p(p), n(n), i(i), pc(pc), sp(sp) {};
		byte* p;
		unsigned n;
		Instruction i;
		uint64_t pc;
		u256* sp;
	};
	InnerState execInner(rmword& io_gas, ExtVMFace& _ext, OnOpFunc const& _onOp, InnerState _in);

	static std::array<InstructionMetric, 256> metrics();
	void makeJumpDestTable(ExtVMFace& _ext);
	uint64_t verifyJumpDest(u256 const& _dest);
	void copyDataToMemory(bytesConstRef _data, u256*& SP);
	void checkRequirements(u256& io_gas, ExtVMFace& _ext, OnOpFunc const& _onOp, Instruction _inst);
	void requireMem(unsigned _n) { if (m_mem.size() < _n) { m_mem.resize(_n); } }

	std::unordered_set<uint64_t> m_jumpDests;
	std::function<void()> m_onFail;
	EVMSchedule const* m_schedule = nullptr;

	// space for memory
	bytes m_mem;

	// space for stack
	u256s m_stack_vector;
	u256* m_stack;
	u256** m_pSP = 0;

	// state of the metering and memorizing
	uint64_t runGas = 0;
	uint64_t newMemSize = 0;
	uint64_t copySize = 0;
	
	
};

void throwVMException(VMException);

}
}