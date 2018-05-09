package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcjson"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/rpcclient"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

var (
	flagset       = flag.NewFlagSet("", flag.ExitOnError)
	notxindexFlag = flagset.Bool("notxindex", false, "use a block explorer to download others' files without txindex")
	hostFlag      = flagset.String("host", "localhost", "(optional) host[:port] of Bitcoin Cash wallet RPC server")
	rpcuserFlag   = flagset.String("rpcuser", "bitcoinrpc", "username for wallet RPC authentication")
	rpcpassFlag   = flagset.String("rpcpass", "", "password for wallet RPC authentication")
	// btcdFlag             = flagset.Bool("lib", true, "should use the built in library instead of RPC wallet, if possible?")
	//btcdFlag             = flagset.Bool("lib", true, "should use the built in library instead of RPC wallet, if possible?")
	ignorechecksumFlag   = flagset.Bool("ignorechecksum", false, "should ignore the warning and continue if the checksum doesn't match?")
	testnetFlag          = flagset.Bool("testnet", false, "Testnetto?")
	overwriteFlag        = flagset.Bool("overwrite", true, "should overwrite while downloading a file, if needed?")
	feeperkbFlag         = flagset.Float64("feeperkb", 1e-5, "fee per kB, in BCH")
	outputvalueFlag      = flagset.Float64("outputvalue", 0.00000547, "output value, don't change to save money!")
	multisigmFlag        = flagset.Int64("multisig.m", 1, "\"M\" of M-of-N multisig outputs [-1<m<(n+1)]")
	multisignFlag        = flagset.Int64("multisig.n", 3, "\"N\" of M-of-N multisig outputs, don't change to save money! [0<n<21]")
	broadcastFlag        = flagset.Int64("broadcast", 0, "broadcast the transaction? 0=ask, 1=print, 2=broadcast")
	walletpassphraseFlag = flagset.String("walletpassphrase" /*""*/, "", "walletpassphrase, if the wallet is locked")
	legacymodeFlag       = flagset.Bool("legacymode" /*""*/, false, "compatible to shirrif's tools, or the new format?")
	//compatmodeFlag       = flagset.Bool("compatmode" /*""*/, false, "compatible to shirrif's tools, or the new format?")
	//promptFlag         = flagset.Uint("prompt", 0, "should make Y/N warning prompts? (default 0=prompt, 1=ignore, 2=abort)")
)

var args []string

func init() {
	flagset.Usage = func() {
		fmt.Println("Usage: FileInDaChain [flags] <upload / download> [cmd args]")
		fmt.Println()
		fmt.Println("Upload arguments:")
		fmt.Println("  <file path (drag N drop)> [where to save the transaction]")
		fmt.Println()
		fmt.Println("Download arguments:")
		fmt.Println("  <TXID OR raw transaction OR raw tx loc> [where to save (folder drag N drop + filename. /path/to/desk/abc.txt)]")
		fmt.Println()
		fmt.Println("Flags:")
		flagset.PrintDefaults()
	}
}

func init() {
	flagset.Parse(os.Args[1:])
	args = flagset.Args()
	if len(args) == 0 {
		flagset.Usage()
		os.Exit(1)
	}
}

func normalizeAddress(addr string, defaultPort string) (hostport string, theError error) {
	if *testnetFlag == true && defaultPort == "8332" {
		defaultPort = "18332"
	}
	host, port, origErr := net.SplitHostPort(addr)
	if origErr == nil {
		return net.JoinHostPort(host, port), nil
	}
	addr = net.JoinHostPort(addr, defaultPort)
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	return addr, nil
}

func main() {
	err, showUsage := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	if showUsage {
		flagset.Usage()
	}
	if err != nil || showUsage {
		os.Exit(1)
	}
}

func run() (theError error, showUsage bool) {
	connect, err := normalizeAddress(*hostFlag, "8332")
	if err != nil {
		return fmt.Errorf("wallet server address: %v", err), true
	}
	connConfig := &rpcclient.ConnConfig{
		Host:         connect,
		User:         *rpcuserFlag,
		Pass:         *rpcpassFlag,
		DisableTLS:   true,
		HTTPPostMode: true,
	}
	var c *rpcclient.Client
	c, err = rpcclient.New(connConfig, nil)
	if err != nil {
		return fmt.Errorf("rpc connect: %v", err), false
	}
	defer func() {
		c.Shutdown()
		c.WaitForShutdown()
	}()
	if strings.ToLower(args[0]) != "download" && strings.ToLower(args[0]) != "upload" {
		return fmt.Errorf("unknown command %v", args[0]), true
	}
	if len(args) == 1 || (strings.ToLower(args[0]) == "upload" && len(args) > 3) || (strings.ToLower(args[0]) == "download" && len(args) > 3) {
		return fmt.Errorf("unexpected syntax"), true
	}
	if strings.ToLower(args[0]) == "download" {
		return downloadAndParse(c)
	}
	if strings.ToLower(args[0]) == "upload" {
		err, showUsage := uploadChecks()
		if err != nil {
			return err, showUsage
		}
		return upload(c)
	}
	return fmt.Errorf("unexpected syntax"), true
}

func downloadAndParse(c *rpcclient.Client) (theError error, showUsage bool) {
	txidOrRawTx, err := hex.DecodeString(args[1])
	//if err != nil || len(txidOrRawTx) < chainhash.HashSize /*32*/ {
	//	return fmt.Errorf("expected a TXID or a raw tx. Unexpected argument: %v", args[1]), false
	if err != nil {
		txidOrRawTx, err = ioutil.ReadFile(args[1])
		if err != nil {
			return fmt.Errorf("The file couldn't be opened!: %v", err), false
		}
	}
	if len(txidOrRawTx) > chainhash.HashSize {
		// is raw TX
		rawtx, err := c.DecodeRawTransaction(txidOrRawTx)
		if err != nil {
			return fmt.Errorf("Raw TX error: %v", err), false
		}
		return parseRawTx(c, rawtx)
	} else {
		// is TXID
		hash, err := chainhash.NewHashFromStr(args[1])
		if err != nil {
			return fmt.Errorf("TXID error: %v", err), false
		}
		var rawtx *btcjson.TxRawResult
		rawtx, err = c.GetRawTransactionVerbose(hash)
		if err != nil {
			if *notxindexFlag == true {
				var explorers [2]string
				var last_explorer int
				if !*testnetFlag {
					explorers[0] = "https://bitcoincash.blockexplorer.com/api/rawtx/"
					explorers[1] = "https://blockdozer.com/insight-api/rawtx/"
					last_explorer = 1
				} else {
					explorers[0] = "https://tbch.blockdozer.com/insight-api/rawtx/"
					last_explorer = 1
				}
				var response *http.Response
				for i, explorer := range explorers {
					response, err = http.Get(explorer + args[1])
					if err != nil || response.StatusCode != 200 {
						if i != last_explorer {
							continue
						}
						if err != nil {
							return err, false
						} else {
							output, err := ioutil.ReadAll(response.Body)
							if err != nil {
								return fmt.Errorf("Error while parsing error: %v", err), false
							}
							defer response.Body.Close()
							return fmt.Errorf("Block explorer error: %v", string(output)), false
						}
						return fmt.Errorf("Probably invalid TXID??: %v", err), false
					}
					defer response.Body.Close()
					break
				}
				output, err := ioutil.ReadAll(response.Body)
				if err != nil {
					return fmt.Errorf("Error while parsing transaction: %v", err), false
				}
				txidOrRawTx, err := hex.DecodeString(string(output[10 : len(output)-2]))
				if err != nil {
					return fmt.Errorf("Acquired hex raw TX error: %v", err), false
				}
				rawtx, err := c.DecodeRawTransaction(txidOrRawTx)
				if err != nil {
					return fmt.Errorf("Acquired raw TX decoding error: %v", err), false
				}
				return parseRawTx(c, rawtx)
			}
			return fmt.Errorf("TXID error: %v. Enabling the -notxindex flag would probably solve this issue", err), false
		}
		return parseRawTx(c, rawtx)
	}
}

func getBytesOfTransaction(nOfLastOutput int, rawtx *btcjson.TxRawResult) ([]byte, error) {
	var bytes []byte
	for _, rawtxVout := range rawtx.Vout[0:nOfLastOutput] { // -2: the last output is the change
		splittedStrings := strings.Split(rawtxVout.ScriptPubKey.Asm, " ")
		for _, eachString := range splittedStrings {
			if !strings.HasPrefix(eachString, "O") && len(eachString) > 30 {
				k, err := hex.DecodeString(eachString)
				if err != nil {
					return nil, fmt.Errorf("%v", err)
				}
				for _, eachByte := range k {
					bytes = append(bytes, eachByte)
				}
			}
		}
	}
	return bytes, nil
}

func parseRawTx(c *rpcclient.Client, rawtx *btcjson.TxRawResult) (theError error, showUsage bool) {
	var bytes []byte
	var nOfLastOutput int
	if *legacymodeFlag {
		nOfLastOutput = len(rawtx.Vout) - 2
	} else {
		nOfLastOutput = len(rawtx.Vout) - 1
	}
	bytes, err := getBytesOfTransaction(nOfLastOutput, rawtx)
	if err != nil {
		return err, false
	}
	length := binary.LittleEndian.Uint32(bytes[0:4])
	checksum := binary.LittleEndian.Uint32(bytes[4:8])
	data := bytes[8 : 8+length]
	if a := crc32.ChecksumIEEE(data); a != checksum {
		fmt.Printf("Expected checksum %v while data checksum %v. ", checksum, a)
		if *ignorechecksumFlag {
			fmt.Println("Ignoring and continuing.")
		} else {
			return fmt.Errorf("Are you sure that this is the right transaction? If you want to ignore the checksum, run with the --ignorechecksum flag."), false
		}
	}
	if len(args) == 3 {
		_, err := os.Stat(args[2])
		if os.IsNotExist(err) || *overwriteFlag {
			fmt.Printf("File writing (loc: %v) in progress...", args[2])
			ioutil.WriteFile(args[2], []byte(string(data)), 0644)
			fmt.Println("Done!")
		}
	} else {
		if len(string(data)) > 10000 {
			fmt.Println("Data too long! Can't print!")
		} else {
			fmt.Println("---DATA START---")
			fmt.Println(string(data))
			fmt.Println("---DATA END---")
		}
	}
	return nil, false
}

func upload(c *rpcclient.Client) (theError error, showUsage bool) {
	fileData, err := ioutil.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("file error: %v", err), false
	}
	if len(fileData) > 95000 {
		return fmt.Errorf("File to be uploaded is bigger than 95 kB"), false
	}
	aTemp := make([]byte, 4)
	binary.LittleEndian.PutUint32(aTemp, uint32(len(fileData)))
	bTemp := make([]byte, 4)
	binary.LittleEndian.PutUint32(bTemp, crc32.ChecksumIEEE(fileData))
	data := append(append(aTemp, bTemp[:]...), fileData[:]...)
	tx := wire.NewMsgTx( /*txVersion*/ 1)
	whereData := uint32(0)
	lenData := uint32(len(data))
	partSize := 65 * (uint32(*multisignFlag))
	for lenData-whereData > partSize {
		k, err := multisigScript(*multisigmFlag, *multisignFlag, data[whereData:whereData+65*uint32(*multisignFlag)])
		if err != nil {
			return fmt.Errorf("internal error1: %v", err), false
		}
		tx.AddTxOut(wire.NewTxOut(int64(*outputvalueFlag*1e8), k))
		whereData += 65 * uint32(*multisignFlag)
	}
	if lenData != whereData+1 {
		// 220
		if (lenData - whereData) < 0 /*https://bitcoin.org/en/developer-guide#null-data*/ {
			k, _ := opReturnScript(data[whereData:lenData])
			tx.AddTxOut(wire.NewTxOut(0, k))
		} else {
			lastNofMultisig := int64((lenData - whereData) / 65)
			if (lenData-whereData)%65 != 0 {
				lastNofMultisig += 1
			}
			if *multisigmFlag > lastNofMultisig {
				multisigmFlag = &lastNofMultisig
				// TODO: pointer
			}
			k, err := multisigScript(*multisigmFlag, lastNofMultisig, data[whereData:lenData])
			if err != nil {
				return fmt.Errorf("internal error23: %v", err), false
			}
			tx.AddTxOut(wire.NewTxOut(int64(*outputvalueFlag*1e8), k))
		}
	}
	// Note: Why am I not deleting this???
	//txSize := estimateRefundSerializeSize(contract, refundTx.TxOut)
	/*changeAddress, err := getRawChangeAddress(c)
	if err != nil {
		return fmt.Errorf("internal error3: %v", err), false
	}
	changeScript, err := txscript.PayToAddrScript(changeAddress)
	if err != nil {
		return fmt.Errorf("internal error4: %v", err), false
	}
	tx.AddTxOut(wire.NewTxOut(0, changeScript))
	*/
	// fundRawTransaction already does that
	amount, err := btcutil.NewAmount(*feeperkbFlag + 3e-8)
	if err != nil {
		return err, false
	}
	txTemp, txFee, err := fundRawTransaction(c, tx, amount)
	if err != nil {
		return err, false
	}
	var outTemp *wire.TxOut
	for _, element := range txTemp.TxOut {
		if notContainsOut(tx.TxOut[:], element) {
			if outTemp == nil {
				outTemp = element
			} else { // assert fundRawTransaction adds only one output
				return fmt.Errorf("Internal error"), false
			}
		}
	}
	var inTemp []*wire.TxIn
	for _, element := range txTemp.TxIn {
		if notContainsIn(tx.TxIn, element) {
			inTemp = append(inTemp, element)
		}
	}
	for _, element := range inTemp {
		tx.TxIn = append(tx.TxIn, element)
	}
	if outTemp != nil {
		tx.TxOut = append(tx.TxOut, outTemp)
	}
	if *walletpassphraseFlag != "" {
		c.WalletPassphrase(*walletpassphraseFlag, 1)
	}
	tx, complete, err := c.SignRawTransaction(tx)
	if err != nil {
		return fmt.Errorf("signrawtransaction: %v", err), false
	}
	if !complete {
		return fmt.Errorf("signrawtransaction: failed to completely sign contract transaction"), false
	}
	fmt.Printf("Transaction size: %0.3f KB\n", float64(tx.SerializeSize())/1e3)
	fmt.Printf("Total fees (may be less than this value): %0.8f\n", txFee.ToBTC()+*outputvalueFlag*float64(len(tx.TxOut)-1))
	fmt.Printf("Transaction fee (may be less than this value): %0.8f (%0.8f BCH/kB)\n", txFee.ToBTC(), txFee.ToBTC()*1e3/float64(tx.SerializeSize()))
	fmt.Printf("TXID (Don't lose it!): %v\n", tx.TxHash())
	var txBuf bytes.Buffer
	txBuf.Grow(tx.SerializeSize())
	tx.Serialize(&txBuf)
	if *broadcastFlag == 0 {
		k := fmt.Sprintf("Raw transaction:\n%x\n", &txBuf)
		if len(k) > 40000 {
			fmt.Println("Transaction too large! Can't print it!")
		} else {
			fmt.Print(k)
		}
		if yesNoPrompt("Do you want to publish it? (Y/n)") {
			_, err := c.SendRawTransaction(tx, true)
			if err != nil {
				fmt.Printf("An error has occured while publishing it: %v", err)
			}
		}
	} else if *broadcastFlag == 1 {
		fmt.Println("---START---")
		fmt.Println(tx)
		fmt.Println("---END---")
	} else /*2*/ {
		c.SendRawTransaction(tx, true)
	}
	if len(args) == 3 {
		_, err := os.Stat(args[2])
		if !os.IsNotExist(err) && !*overwriteFlag {
			return fmt.Errorf("A file exists at: %v", args[2]), false
		} else {
			fmt.Printf("Writing transaction (loc: %v) in progress...", args[2])
			ioutil.WriteFile(args[2], []byte(fmt.Sprintf("%x", &txBuf)), 0644)
			fmt.Println("Done!")
			// TODO: remove
			/*k, err := c.DecodeRawTransaction(txBuf.Bytes())
			if err == nil {
				var stringsNeeded []string
				for _, v := range k.Vout {
					stringsNeeded = append(stringsNeeded, v.ScriptPubKey.Asm)
				}
				fmt.Print("%v", stringsNeeded)
			} else {
				fmt.Print("%v", err)
			}*/
		}
	}
	return nil, false
}

func areSame(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func notContainsOut(s []*wire.TxOut, e *wire.TxOut) bool {
	for _, a := range s {
		if areSame(a.PkScript, e.PkScript) {
			return false
		}
	}
	return true
}

func notContainsIn(s []*wire.TxIn, e *wire.TxIn) bool {
	for _, a := range s {
		if areSame(a.SignatureScript, e.SignatureScript) {
			return false
		}
	}
	return true
}

func fundRawTransaction(c *rpcclient.Client, tx *wire.MsgTx, feePerKb btcutil.Amount) (fundedTx *wire.MsgTx, fee btcutil.Amount, err error) {
	var buf bytes.Buffer
	buf.Grow(tx.SerializeSize())
	tx.Serialize(&buf)
	fmt.Printf("%x", &buf)
	param0, err := json.Marshal(hex.EncodeToString(buf.Bytes()))
	if err != nil {
		return nil, 0, err
	}
	param1, err := json.Marshal(struct {
		FeeRate float64 `json:"feeRate"`
	}{
		FeeRate: feePerKb.ToBTC(),
	})
	if err != nil {
		return nil, 0, err
	}
	params := []json.RawMessage{param0, param1}
	rawResp, err := c.RawRequest("fundrawtransaction", params)
	if err != nil {
		rawResp, err := c.RawRequest("fundrawtransaction", []json.RawMessage{param0})
		if err != nil {
			return nil, 0, err
		}
		fmt.Println("warning: your node (probably Bitcoin Unlimited) doesn't support setting fees manually.")
		fmt.Println("Consider using Bitcoin ABC, if you want to set fees manually (this warning may be ignored safely).")
		return fundTransactionJsonParser(rawResp)
	}
	return fundTransactionJsonParser(rawResp)
}

func fundTransactionJsonParser(rawResp json.RawMessage) (fundedTx *wire.MsgTx, fee btcutil.Amount, err error) {
	var resp struct {
		Hex       string  `json:"hex"`
		Fee       float64 `json:"fee"`
		ChangePos float64 `json:"changepos"`
	}
	err = json.Unmarshal(rawResp, &resp)
	if err != nil {
		return nil, 0, err
	}
	fundedTxBytes, err := hex.DecodeString(resp.Hex)
	if err != nil {
		return nil, 0, err
	}
	fundedTx = &wire.MsgTx{}
	err = fundedTx.Deserialize(bytes.NewReader(fundedTxBytes))
	if err != nil {
		return nil, 0, err
	}
	feeAmount, err := btcutil.NewAmount(resp.Fee)
	if err != nil {
		return nil, 0, err
	}
	return fundedTx, feeAmount, nil
}

func getRawChangeAddress(c *rpcclient.Client) (btcutil.Address, error) {
	// TODO: Simplify
	rawResp, err := c.RawRequest("getrawchangeaddress", nil)
	if err != nil {
		return nil, err
	}
	var addrStr string
	err = json.Unmarshal(rawResp, &addrStr)
	if err != nil {
		return nil, err
	}
	addr, err := btcutil.DecodeAddress(addrStr, &chaincfg.MainNetParams)
	if err != nil {
		return nil, err
	}
	if !addr.IsForNet(&chaincfg.MainNetParams) {
		return nil, fmt.Errorf("address %v is not intended for use on %v",
			addrStr, (&chaincfg.MainNetParams).Name)
	}
	return addr, nil
}

func multisigScript(m int64, n int64, bytes []byte) ([]byte, error) {
	if int64(len(bytes)) > n*65 /*|| len(bytes)%64 != 0*/ {
		return nil, fmt.Errorf("Unknown error!")
	}
	if len(bytes)%65 != 0 {
		bytes = append(bytes, make([]byte, 65-(len(bytes)%65))...)
	}
	script := txscript.NewScriptBuilder()
	script.AddInt64(m)
	for i := 0; i < len(bytes); i += 65 {
		//script.AddData(append([]byte{0x04}, bytes[i : i+64]...))
		script.AddData(bytes[i : i+65])
	}
	script.AddInt64(n)
	script.AddOp(txscript.OP_CHECKMULTISIG)
	return script.Script()
}

func opReturnScript(bytes []byte) ([]byte, error) {
	script := txscript.NewScriptBuilder()
	script.AddOp(txscript.OP_RETURN)
	script.AddData(bytes)
	return script.Script()
}

func uploadChecks() (theError error, showUsage bool) {
	if *broadcastFlag < 0 || *broadcastFlag > 2 {
		return fmt.Errorf("The broadcast flag must be either 0 (ask), 1 (print), 2 (submit)"), false
	}
	if *outputvalueFlag < 1e-8 || *outputvalueFlag > 1 {
		return fmt.Errorf("The outputvalue flag must be between 0.00000001 and 1 BCH"), false
	}
	if *multisignFlag < 1 || *multisignFlag > 20 {
		return fmt.Errorf("The multisig.n flag must be between 1 and 20 (inclusive)"), false
	}
	if *multisignFlag > 3 {
		fmt.Println("WARNING: The multisig.n flag can't be more than 3 unless you're a miner")
	}
	if *multisigmFlag < 0 || *multisigmFlag > *multisignFlag {
		return fmt.Errorf("The multisig.m flag must be between 0 and multisig.n (default: 20) (inclusive)"), false
	}
	if *feeperkbFlag != 1e-5 {
		float, err := strconv.ParseFloat(args[2], 64)
		if err != nil {
			return fmt.Errorf("expected a fee/kb (in BCH units) float as an optional second argument, but got a Not-A-Number: %v", os.Args[2]), false
		}
		if float < 1e-5 {
			return fmt.Errorf("please set a higher fee"), false
		}
		if float > 1e-3 {
			fmt.Println("warning: very high fee. Ignoring and continuing.")
		}
	}
	_, err := os.Stat(args[1])
	if os.IsNotExist(err) {
		return fmt.Errorf("File does not exist: %v", os.Args[1]), false
	} else if err != nil {
		return fmt.Errorf("File path error: %v", err), false
	}
	return nil, false
}

func yesNoPrompt(a string) bool {
	fmt.Printf(a)
	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println(err)
		return yesNoPrompt(a)
	}
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer == "y" || answer == "yes" {
		return true
	}
	if answer == "n" || answer == "no" {
		return false
	}
	return yesNoPrompt(a)
}
