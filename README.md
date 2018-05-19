# FileInDaChain

A CLI tool to upload *any* data shorter than 90 kB to the blockchain.

Uses Omni's Class B transactions (can you spot the difference?) and OP_RETURNs,
depending on feasibility.

```
Usage: FileInDaChain [flags] <upload / download> [cmd args]

Upload arguments:
  <file path (drag N drop)> [where to save the transaction]

Download arguments:
  <TXID OR raw transaction OR raw tx loc> [where to save (folder drag N drop + filename. /path/to/desk/abc.txt)]

Flags:
  -broadcast int
    	broadcast the transaction? 0=ask, 1=print, 2=broadcast
  -feeperkb float
    	fee per kB, in BCH (default 1e-05)
  -host string
    	(optional) host[:port] of Bitcoin Cash wallet RPC server (default "localhost")
  -ignorechecksum
    	should ignore the warning and continue if the checksum doesn't match?
  -legacymode
    	compatible to shirrif's tools, or the new format?
  -multisig.m int
    	"M" of M-of-N multisig outputs [-1<m<(n+1)] (default 1)
  -multisig.n int
    	"N" of M-of-N multisig outputs, don't change to save money! [0<n<21] (default 3)
  -notxindex
    	use a block explorer to download others' files without txindex
  -outputvalue float
    	output value, don't change to save money! (default 5.47e-06)
  -overwrite
    	should overwrite while downloading a file, if needed? (default true)
  -rpcpass string
    	password for wallet RPC authentication
  -rpcuser string
    	username for wallet RPC authentication (default "bitcoinrpc")
  -testnet
    	Testnetto?
  -walletpassphrase string
    	walletpassphrase, if the wallet is locked
```

By using this software, you agree to not to upload/download anything illegal in any region!

Use it at your own risk!

```
THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

Sample (JPG, testnet): cd600cbbb73426b906a58818bc2f30fb396d048809915f7149c23db03859562b
