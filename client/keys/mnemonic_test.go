package keys

import (
	"bufio"
	"fmt"
	"github.com/tendermint/tendermint/crypto/ed25519"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/client"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func Test_RunMnemonicCmdNormal(t *testing.T) {
	cmdBasic := mnemonicKeyCommand()
	fmt.Println("--cmdBasic:--",cmdBasic)
	err := runMnemonicCmd(cmdBasic, []string{})
	require.NoError(t, err)


	priv := ed25519.GenPrivKey()
	addr := sdk.AccAddress(priv.PubKey().Address())
	fmt.Println("private:",priv)//private: [129 153 230 119 103 217 16 139 188 248 239 174 207 20 150 20 122 147 254 201 215 45 129 114 236 115 87 78 25 245 103 248 68 178 201 22 78 183 126 30 91 153 151 23 17 79 14 19 67 208 139 49 226 108 216 28 167 130 59 231 202 40 81 9]
	fmt.Println("pubkey:",priv.PubKey()) //publicKey:44B2C9164EB77E1E5B999717114F0E1343D08B31E26CD81CA7823BE7CA285109
	fmt.Println("hex_address:",addr)//hex_address:8CA5D0BB957EC838FD872312FE2D81D48D078EDC


	acc := sdk.AccAddress(priv.PubKey().Address())
	res := sdk.AccAddress{}

	testMarshal(t, &acc, &res, acc.MarshalJSON, (&res).UnmarshalJSON)
	testMarshal(t, &acc, &res, acc.Marshal, (&res).Unmarshal)

	str := acc.String()
	fmt.Println("---您好，已经获取到了地址----：",str)

}

func Test_RunMnemonicCmdUser(t *testing.T) {
	cmdUser := mnemonicKeyCommand()
	err := cmdUser.Flags().Set(flagUserEntropy, "1")
	assert.NoError(t, err)

	err = runMnemonicCmd(cmdUser, []string{})
	require.Error(t, err)
	require.Equal(t, "EOF", err.Error())

	// Try again
	cleanUp := client.OverrideStdin(bufio.NewReader(strings.NewReader("Hi!\n")))
	defer cleanUp()
	err = runMnemonicCmd(cmdUser, []string{})
	require.Error(t, err)
	require.Equal(t,
		"256-bits is 43 characters in Base-64, and 100 in Base-6. You entered 3, and probably want more",
		err.Error())

	// Now provide "good" entropy :)
	fakeEntropy := strings.Repeat(":)", 40) + "\ny\n" // entropy + accept count
	cleanUp2 := client.OverrideStdin(bufio.NewReader(strings.NewReader(fakeEntropy)))
	defer cleanUp2()
	err = runMnemonicCmd(cmdUser, []string{})
	require.NoError(t, err)

	// Now provide "good" entropy but no answer
	fakeEntropy = strings.Repeat(":)", 40) + "\n" // entropy + accept count
	cleanUp3 := client.OverrideStdin(bufio.NewReader(strings.NewReader(fakeEntropy)))
	defer cleanUp3()
	err = runMnemonicCmd(cmdUser, []string{})
	require.Error(t, err)

	// Now provide "good" entropy but say no
	fakeEntropy = strings.Repeat(":)", 40) + "\nn\n" // entropy + accept count
	cleanUp4 := client.OverrideStdin(bufio.NewReader(strings.NewReader(fakeEntropy)))
	defer cleanUp4()
	err = runMnemonicCmd(cmdUser, []string{})
	require.NoError(t, err)
}
