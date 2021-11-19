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

#pragma once

#include "Instruction.h"

#include <mcp/lib/numbers.hpp>
#include <mcp/lib/EVMSchedule.h>
#include <mcp/lib/LogEntry.h>
#include <mcp/node/utility.hpp>
#include <mcp/db/database.hpp>
#include <libdevcore/Common.h>
#include <libdevcore/CommonData.h>
#include <libdevcore/SHA3.h>

#include <evmc/include/evmc/evmc.h>

#include <boost/optional.hpp>
#include <functional>
#include <set>

namespace mcp
{
    class node;
    class ledger;
    class iblock_cache;
}

namespace dev
{
namespace eth
{

/// Reference to a slice of buffer that also owns the buffer.
///
/// This is extension to the concept C++ STL library names as array_view
/// (also known as gsl::span, array_ref, here vector_ref) -- reference to
/// continuous non-modifiable memory. The extension makes the object also owning
/// the referenced buffer.
///
/// This type is used by VMs to return output coming from RETURN instruction.
/// To avoid memory copy, a VM returns its whole memory + the information what
/// part of this memory is actually the output. This simplifies the VM design,
/// because there are multiple options how the output will be used (can be
/// ignored, part of it copied, or all of it copied). The decision what to do
/// with it was moved out of VM interface making VMs "stateless".
///
/// The type is movable, but not copyable. Default constructor available.
class owning_bytes_ref: public vector_ref<byte const>
{
public:
    owning_bytes_ref() = default;

    /// @param _bytes  The buffer.
    /// @param _begin  The index of the first referenced byte.
    /// @param _size   The number of referenced bytes.
    owning_bytes_ref(bytes&& _bytes, size_t _begin, size_t _size):
            m_bytes(std::move(_bytes))
    {
        // Set the reference *after* the buffer is moved to avoid
        // pointer invalidation.
        retarget(&m_bytes[_begin], _size);
    }

    owning_bytes_ref(owning_bytes_ref const&) = delete;
    owning_bytes_ref(owning_bytes_ref&&) = default;
    owning_bytes_ref& operator=(owning_bytes_ref const&) = delete;
    owning_bytes_ref& operator=(owning_bytes_ref&&) = default;

    /// Moves the bytes vector out of here. The object cannot be used any more.
    bytes&& takeBytes()
    {
        reset();  // Reset reference just in case.
        return std::move(m_bytes);
    }

private:
    bytes m_bytes;
};

struct SubState
{
    std::set<mcp::account> suicides;    ///< Any accounts that have suicided.
    LogEntries logs;            ///< Any logs.
    u256 refunds;                ///< Refund counter of SSTORE nonzero->zero.

    SubState& operator+=(SubState const& _s)
    {
        suicides += _s.suicides;
        refunds += _s.refunds;
        logs += _s.logs;
        return *this;
    }

    void clear()
    {
        suicides.clear();
        logs.clear();
        refunds = 0;
    }
};

class ExtVMFace;
class LastBlockHashesFace;
class VMFace;

using OnOpFunc = std::function<void(uint64_t /*steps*/, uint64_t /* PC */, Instruction /*instr*/, bigint /*newMemSize*/, bigint /*gasCost*/, bigint /*gas*/, VMFace const*, ExtVMFace const*)>;

struct CallParameters
{
    CallParameters() = default;
    CallParameters(
        mcp::account _senderAddress,
        mcp::account _codeAddress,
        mcp::account _receiveAddress,
        u256 _valueTransfer,
        u256 _apparentValue,
        u256 _gas,
        bytesConstRef _data,
        OnOpFunc _onOpFunc
    ):    senderAddress(_senderAddress), codeAddress(_codeAddress), receiveAddress(_receiveAddress),
        valueTransfer(_valueTransfer), apparentValue(_apparentValue), gas(_gas), data(_data), onOp(_onOpFunc)  {}
    mcp::account senderAddress;
    mcp::account codeAddress;
    mcp::account receiveAddress;
    u256 valueTransfer;
    u256 apparentValue;
    u256 gas;
    bytesConstRef data;
    bool staticCall = false;
    OnOpFunc onOp;
};


class McInfo
{
public:
	McInfo() = default;
	McInfo(uint64_t const & mci_a, uint64_t const & mc_timestamp_a) :
		mci(mci_a),
		mc_timestamp(mc_timestamp_a)
	{
	};

	uint64_t mci;
	uint64_t mc_timestamp;
};


class EnvInfo
{
public:
    EnvInfo(mcp::db::db_transaction & transaction_a, mcp::node & node_a, std::shared_ptr<mcp::iblock_cache> cache_a, McInfo const & mci_info_a)
    :transaction(transaction_a),node(node_a),cache(cache_a), m_mci_info(mci_info_a)
    {};

    mcp::db::db_transaction & transaction;
    mcp::node &node;
    std::shared_ptr<mcp::iblock_cache> cache;

    uint64_t mci() const { return m_mci_info.mci; }
    uint64_t timestamp() const { return m_mci_info.mc_timestamp; }

private:
	McInfo m_mci_info;
};

/// Represents a call result.
///
/// @todo: Replace with evmc_result in future.
struct CallResult
{
    evmc_status_code status;
    owning_bytes_ref output;

    CallResult(evmc_status_code status, owning_bytes_ref&& output)
      : status{status}, output{std::move(output)}
    {}
};

/// Represents a CREATE result.
///
/// @todo: Replace with evmc_result in future.
struct CreateResult
{
    evmc_status_code status;
    owning_bytes_ref output;
    mcp::account address;

    CreateResult(evmc_status_code status, owning_bytes_ref&& output, mcp::account const& address)
        : status{status}, output{std::move(output)}, address{address}
    {}
};

/**
 * @brief Interface and null implementation of the class for specifying VM externalities.
 */
class ExtVMFace: public evmc_context
{
public:
    /// Full constructor.
    ExtVMFace(EnvInfo const& _envInfo, mcp::account _myAddress, mcp::account _caller, mcp::account _origin,
        u256 _value, u256 _gasPrice, bytesConstRef _data, bytes _code, h256 const& _codeHash,
        unsigned _depth, bool _isCreate, bool _staticCall);

    virtual ~ExtVMFace() = default;

    ExtVMFace(ExtVMFace const&) = delete;
    ExtVMFace& operator=(ExtVMFace const&) = delete;

    /// Read storage location.
    virtual u256 store(u256) { return 0; }

    /// Write a value in storage.
    virtual void setStore(u256, u256) {}

    /// Read original storage value (before modifications in the current transaction).
    virtual u256 originalStorageValue(u256 const&) { return 0; }

    /// Read address's balance.
    virtual u256 balance(mcp::account) { return 0; }

    /// Read address's code.
    virtual bytes const& codeAt(mcp::account) { return NullBytes; }

    /// @returns the size of the code in bytes at the given address.
    virtual size_t codeSizeAt(mcp::account) { return 0; }

    /// @returns the hash of the code at the given address.
    virtual h256 codeHashAt(mcp::account) { return h256{}; }

    /// Does the account exist?
    virtual bool exists(mcp::account) { return false; }

    /// Suicide the associated contract and give proceeds to the given address.
    virtual void suicide(mcp::account) { sub.suicides.insert(myAddress); }

    /// Create a new (contract) account.
    virtual CreateResult create(u256, u256&, bytesConstRef, Instruction, u256, OnOpFunc const&) = 0;

    /// Make a new message call.
    virtual CallResult call(CallParameters&) = 0;

    /// Revert any changes made (by any of the other calls).
    virtual void log(h256s&& _topics, bytesConstRef _data) { sub.logs.push_back(LogEntry(myAddress, std::move(_topics), _data.toBytes())); }

    virtual h256 mcBlockHash(h256 mci_a) = 0;

    /// Get the execution environment information.
    EnvInfo const& envInfo() const { return m_envInfo; }

    /// Return the EVM gas-price schedule for this execution context.
    virtual EVMSchedule const& evmSchedule() const { return ConstantinopleFixSchedule; }

private:
    EnvInfo const& m_envInfo;

public:
    // TODO: make private
    mcp::account myAddress;  ///< Address associated with executing code (a contract, or contract-to-be).
    mcp::account caller;     ///< Address which sent the message (either equal to origin or a contract).
    mcp::account origin;     ///< Original transactor.
    u256 value;         ///< Value (in Wei) that was passed to this address.
    u256 gasPrice;      ///< Price of gas (that we already paid).
    bytesConstRef data;       ///< Current input data.
    bytes code;               ///< Current code that is executing.
    h256 codeHash;            ///< SHA3 hash of the executing code
    u256 salt;                ///< Values used in new address construction by CREATE2 
    SubState sub;             ///< Sub-band VM state (suicides, refund counter, logs).
    unsigned depth = 0;       ///< Depth of the present call.
    bool isCreate = false;    ///< Is this a CREATE call?
    bool staticCall = false;  ///< Throw on state changing.
};

inline evmc_address toEvmC(mcp::account const& _addr)
{
    return reinterpret_cast<evmc_address const&>(_addr);
}

inline evmc_uint256be toEvmC(h256 const& _h)
{
    return reinterpret_cast<evmc_uint256be const&>(_h);
}

inline u256 fromEvmC(evmc_uint256be const& _n)
{
    return fromBigEndian<u256>(_n.bytes);
}

inline mcp::account fromEvmC(evmc_address const& _addr)
{
    return reinterpret_cast<mcp::account const&>(_addr);
}
}
}
