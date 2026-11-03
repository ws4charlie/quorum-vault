package evm

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Compiled by contracts/build.sh (pinned solc); do not edit by hand.
var (
	//go:embed artifacts/Forwarder.bin
	forwarderBinHex string
	//go:embed artifacts/ForwarderFactory.bin
	factoryBinHex string
	//go:embed artifacts/ForwarderFactory.abi.json
	factoryABIJSON string
	//go:embed artifacts/Forwarder.abi.json
	forwarderABIJSON string
)

var (
	abiOnce     sync.Once
	factoryABI  abi.ABI
	forwarderAB abi.ABI
	erc20ABI    abi.ABI
	abiErr      error
)

const erc20JSON = `[
 {"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"outputs":[{"type":"bool"}],"stateMutability":"nonpayable"},
 {"type":"event","name":"Transfer","inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}]}
]`

func loadABIs() error {
	abiOnce.Do(func() {
		if factoryABI, abiErr = abi.JSON(strings.NewReader(factoryABIJSON)); abiErr != nil {
			return
		}
		if forwarderAB, abiErr = abi.JSON(strings.NewReader(forwarderABIJSON)); abiErr != nil {
			return
		}
		erc20ABI, abiErr = abi.JSON(strings.NewReader(erc20JSON))
	})
	return abiErr
}

// ForwarderCreationCode is the Forwarder's creation bytecode (without constructor args).
func ForwarderCreationCode() []byte { return common.FromHex(strings.TrimSpace(forwarderBinHex)) }

// FactoryCreationCode is the ForwarderFactory's creation bytecode (without constructor args).
func FactoryCreationCode() []byte { return common.FromHex(strings.TrimSpace(factoryBinHex)) }

// FactoryDeployData returns creation code plus the constructor argument
// (destination), ready to send as the data of a contract-creation transaction.
func FactoryDeployData(destination common.Address) []byte {
	return append(FactoryCreationCode(), common.LeftPadBytes(destination.Bytes(), 32)...)
}

// DeriveSalt is keccak256("qv-evm-forwarder-v1" || len(customer) as uint32 ||
// customer || index as uint64), all big-endian. Length-prefixing keeps
// (customer, index) pairs unambiguous.
func DeriveSalt(customerID string, index uint64) [32]byte {
	var b bytes.Buffer
	b.WriteString("qv-evm-forwarder-v1")
	_ = binary.Write(&b, binary.BigEndian, uint32(len(customerID)))
	b.WriteString(customerID)
	_ = binary.Write(&b, binary.BigEndian, index)
	return crypto.Keccak256Hash(b.Bytes())
}

// PredictAddress is ForwarderFactory.predict(salt), computed locally: the
// CREATE2 address of the Forwarder with init code creationCode ++ abi.encode(destination).
func PredictAddress(factory, destination common.Address, salt [32]byte) common.Address {
	init := append(ForwarderCreationCode(), common.LeftPadBytes(destination.Bytes(), 32)...)
	return crypto.CreateAddress2(factory, salt, crypto.Keccak256(init))
}

func packDeployAndFlush(salt [32]byte, tokens []common.Address) ([]byte, error) {
	if err := loadABIs(); err != nil {
		return nil, err
	}
	if tokens == nil {
		tokens = []common.Address{}
	}
	return factoryABI.Pack("deployAndFlush", salt, tokens)
}

func packTransfer(to common.Address, amount *big.Int) ([]byte, error) {
	if err := loadABIs(); err != nil {
		return nil, err
	}
	return erc20ABI.Pack("transfer", to, amount)
}

// unpackDeployAndFlush decodes calldata that must be exactly a deployAndFlush call.
func unpackDeployAndFlush(data []byte) (salt [32]byte, tokens []common.Address, err error) {
	if err = loadABIs(); err != nil {
		return
	}
	m := factoryABI.Methods["deployAndFlush"]
	if len(data) < 4 || !bytes.Equal(data[:4], m.ID) {
		return salt, nil, fmt.Errorf("evm: calldata is not deployAndFlush")
	}
	args, err := m.Inputs.Unpack(data[4:])
	if err != nil || len(args) != 2 {
		return salt, nil, fmt.Errorf("evm: decode deployAndFlush: %v", err)
	}
	salt = args[0].([32]byte)
	tokens = args[1].([]common.Address)
	// Reject any non-canonical encoding (padding, trailing bytes, odd offsets).
	if re, perr := packDeployAndFlush(salt, tokens); perr != nil || !bytes.Equal(re, data) {
		return salt, nil, fmt.Errorf("evm: deployAndFlush calldata is not canonically encoded")
	}
	return salt, tokens, nil
}
