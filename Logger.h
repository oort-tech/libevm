#pragma once
#include "Instruction.h"
#include <libdevcore/Common.h>
#include <libdevcore/Address.h>

namespace mcp { enum class TransactionException; }

namespace dev
{
namespace eth
{
class ExtVMFace;
class VMFace;

// EVMLogger is used to collect execution traces from an EVM transaction
// execution. CaptureState is called for each step of the VM with the
// current VM state.
// Note that reference types are actual VM data structures; make copies
// if you need to retain them beyond the current call.
class EVMLogger
{
public:
    EVMLogger() = default;
    // Transaction level
    virtual void CaptureTxStart(uint64_t _gasLimit) = 0;
    
    virtual void CaptureTxEnd(uint64_t _restGas) = 0;


    // Top call frame
    virtual void CaptureStart(ExtVMFace const* _voidExt, Address const& _from, Address const& _to,
        bool _create, bytes const& _input, uint64_t _gas, u256 _value) = 0;
    
    virtual void CaptureEnd(bytes const&_output, uint64_t _gasUsed, mcp::TransactionException const _excepted) = 0;


    // Rest of call frames
    virtual void CaptureEnter(Instruction _inst, Address const& _from, Address const& _to, 
        bytes const& _input, uint64_t _gas, std::shared_ptr<dev::u256> _value) = 0;
    
    virtual void CaptureExit(bytes const& _output, uint64_t _gasUsed, mcp::TransactionException const _excepted) = 0;


    /// Opcode level
    virtual void CaptureState(uint64_t _PC, Instruction _inst,
        uint64_t _gasCost, uint64_t _gas, VMFace const* _vm, ExtVMFace const* _voidExt) = 0;
    
    virtual void CaptureFault(uint64_t _PC, Instruction _inst,
        uint64_t _gasCost, uint64_t _gas, VMFace const* _vm, ExtVMFace const* _voidExt) = 0;
};
}  // namespace eth
}  // namespace dev
