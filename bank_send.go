package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Quiq/webauthn_proxy/util"
	"github.com/cosmos/cosmos-sdk/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	testutilmod "github.com/cosmos/cosmos-sdk/types/module/testutil"
	txservice "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/bank"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/go-webauthn/webauthn/protocol"
	"google.golang.org/grpc"
	"io"
	"net/http"
	"path/filepath"
	"strings"
)

func init() {
	// Set the Bech32 prefix to "tp"
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("tp", "tp"+sdk.PrefixPublic)
	config.Seal()
}

func GetAccountInfoWebAuthn(grpcConn *grpc.ClientConn, address sdk.AccAddress, cdc codec.Codec) (uint64, uint64, cryptotypes.PubKey, error) {
	authClient := types.NewQueryClient(grpcConn)
	res, err := authClient.Account(context.Background(), &types.QueryAccountRequest{Address: address.String()})
	if err != nil {
		return 0, 0, nil, err
	}

	var acc types.AccountI
	if err := cdc.UnpackAny(res.Account, &acc); err != nil {
		return 0, 0, nil, err
	}

	return acc.GetAccountNumber(), acc.GetSequence(), acc.GetPubKey(), nil
}

func HandleBankSend(w http.ResponseWriter, r *http.Request) {
	_, _, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, loginError, http.StatusBadRequest)
		return
	}

	// Prevents html caching because this page serves two different pages.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
	http.ServeFile(w, r, filepath.Join(staticPath, "bank_send.html"))
}

// ProcessBankSendTransaction handles the bank send transaction with WebAuthn assertion
func ProcessBankSendTransaction(w http.ResponseWriter, r *http.Request) {
	_, _, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, map[string]string{"message": "Invalid origin"}, http.StatusBadRequest)
		return
	}

	// Parse form data
	err = r.ParseForm()
	if err != nil {
		logger.Errorf("Error parsing form: %s", err)
		util.JSONResponse(w, map[string]string{"message": "Invalid form data"}, http.StatusBadRequest)
		return
	}

	// Get parameters
	fromAddr := r.FormValue("from")
	toAddr := r.FormValue("to")
	amount := r.FormValue("amount")
	denom := r.FormValue("denom")
	assertionStr := r.FormValue("assertion")

	if fromAddr == "" || toAddr == "" || amount == "" || denom == "" || assertionStr == "" {
		util.JSONResponse(w, map[string]string{"message": "Missing required parameters"}, http.StatusBadRequest)
		return
	}

	// First unmarshal the string to remove escaping
	var assertionData string
	err = json.Unmarshal([]byte(assertionStr), &assertionData)
	if err != nil {
		logger.Errorf("Error unescaping assertion JSON: %s", err)
		util.JSONResponse(w, map[string]string{"message": "Invalid assertion format"}, http.StatusBadRequest)
		return
	}

	bodyAssertion := io.NopCloser(bytes.NewReader([]byte(assertionData)))
	assertion, err := protocol.ParseCredentialRequestResponseBody(bodyAssertion)
	if err != nil {
		logger.Errorf("Error parsing assertion: %s", err)
		util.JSONResponse(w, map[string]string{"message": "Invalid assertion data"}, http.StatusBadRequest)
		return
	}

	// Log the received data
	logger.Infof("Received bank send request from: %s, to: %s, amount: %s %s", fromAddr, toAddr, amount, denom)

	raw, _ := json.Marshal(assertion.Raw)
	logger.Printf("Raw response which is the signature payload: %s", prettyPrintJSON(raw))
	logger.Printf("base64 encoded signature payload : %s", base64.RawURLEncoding.EncodeToString(raw))
	prettyPrintJSON(raw)
	base64Raw := base64.RawURLEncoding.EncodeToString(raw)
	txHash, err := broadcastToChain(fromAddr, toAddr, amount, denom, base64Raw)
	if err != nil {
		logger.Errorf("Error broadcasting transaction: %s", err)
		util.JSONResponse(w, map[string]string{"message": "Error broadcasting transaction"}, http.StatusInternalServerError)
		return
	}
	// Just return the assertion data for now
	response := map[string]interface{}{
		"message":    "Transaction request received",
		"txHash":     "tx_hash=" + txHash,
		"rawData":    string(prettifyJSON([]byte(assertionStr))),
		"base64Data": assertionStr,
	}

	util.JSONResponse(w, response, http.StatusOK)
}

// Helper function to prettify JSON
func prettifyJSON(data []byte) []byte {
	var i interface{}
	json.Unmarshal(data, &i)
	pretty, _ := json.MarshalIndent(i, "", "  ")
	return pretty
}

// GetBankSendChallenge generates a WebAuthn challenge for bank transactions
func GetBankSendChallenge(w http.ResponseWriter, r *http.Request) {
	// Check origin
	_, _, err := checkOrigin(r)
	if err != nil {
		logger.Errorf("Error validating origin: %s", err)
		util.JSONResponse(w, map[string]string{"message": "Invalid origin"}, http.StatusBadRequest)
		return
	}

	// Get transaction parameters from query string
	fromAddr := r.URL.Query().Get("from")
	toAddr := r.URL.Query().Get("to")
	amount := r.URL.Query().Get("amount")
	denom := r.URL.Query().Get("denom")

	// Validate parameters
	if fromAddr == "" || toAddr == "" || amount == "" || denom == "" {
		util.JSONResponse(w, map[string]string{"message": "Missing required transaction parameters"}, http.StatusBadRequest)
		return
	}

	// Log the transaction details
	logger.Infof("Generating challenge for bank send from: %s, to: %s, amount: %s %s", fromAddr, toAddr, amount, denom)

	challenge, err := createPayloadToSign(fromAddr, toAddr, amount, denom)
	if err != nil {
		logger.Errorf("Error creating payload to sign: %s", err)
		util.JSONResponse(w, map[string]string{"message": "Error creating payload to sign"}, http.StatusInternalServerError)
		return
	}

	// Return the challenge
	util.JSONResponse(w, map[string]string{"challenge": challenge}, http.StatusOK)
}

func createPayloadToSign(fromAddress string, toAddress string, amount string, denom string) (string, error) {
	// Choose your codec: Amino or Protobuf. Here, we use Protobuf, given by the
	// following function.
	encCfg := testutilmod.MakeTestEncodingConfig(bank.AppModuleBasic{}, auth.AppModuleBasic{})

	// Create a new TxBuilder.
	txBuilder := encCfg.TxConfig.NewTxBuilder()
	fromAddressSdk := sdk.MustAccAddressFromBech32(fromAddress)
	toAddressSdk := sdk.MustAccAddressFromBech32(toAddress)

	// make this more dynamic if possible
	// Convert amount string to int64
	amountInt, err := sdk.ParseCoinNormalized(amount + denom)
	if err != nil {
		return "", err
	}
	msgToBroadcast := banktypes.NewMsgSend(fromAddressSdk, toAddressSdk, sdk.NewCoins(amountInt))
	err = txBuilder.SetMsgs(msgToBroadcast)
	if err != nil {
		return "", err
	}

	// Create a connection to the gRPC server.
	grpcConn, _ := grpc.Dial(
		"127.0.0.1:9090",    // Or your gRPC server address.
		grpc.WithInsecure(), // The Cosmos SDK doesn't support any transport security mechanism.
	)
	defer grpcConn.Close()

	txBuilder.SetGasLimit(2000000)
	txBuilder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("nhash", 38400000000)))
	// Get account number and sequence dynamically
	accNum, accSeq, _, err := GetAccountInfoWebAuthn(grpcConn, fromAddressSdk, encCfg.Codec)
	if err != nil {
		return "", err
	}

	accNums := []uint64{accNum}
	accSeqs := []uint64{accSeq}

	var sigsV2 []signing.SignatureV2
	sigV2 := signing.SignatureV2{
		PubKey: nil,
		Data: &signing.SingleSignatureData{
			SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
			Signature: nil,
		},
		Sequence: accSeqs[0],
	}

	sigsV2 = append(sigsV2, sigV2)

	err = txBuilder.SetSignatures(sigsV2...)
	if err != nil {
		return "", err
	}

	signerData := authsigning.SignerData{
		ChainID:       "testing",
		AccountNumber: accNums[0],
		Sequence:      accSeqs[0],
	}

	// Generate the bytes to be signed.
	signBytes, err := authsigning.GetSignBytesAdapter(
		context.TODO(), encCfg.TxConfig.SignModeHandler(), signing.SignMode_SIGN_MODE_DIRECT, signerData, txBuilder.GetTx())
	if err != nil {
		return "", err
	}

	// Compute the SHA-256 hash of the raw bytes and then have the user sign it via a FIDO2 device.
	hash := sha256.Sum256(signBytes)
	txHash := strings.ToUpper(hex.EncodeToString(hash[:]))

	fmt.Printf("Transaction Hash in sig bytes to be signed: %s\n", txHash)
	return txHash, nil
}

func broadcastToChain(fromAddress string, toAddress string, amount string, denom string, signature string) (string, error) {
	encCfg := testutilmod.MakeTestEncodingConfig(bank.AppModuleBasic{}, auth.AppModuleBasic{})

	// Create a new TxBuilder.
	txBuilder := encCfg.TxConfig.NewTxBuilder()
	fromAddressSdk := sdk.MustAccAddressFromBech32(fromAddress)
	toAddressSdk := sdk.MustAccAddressFromBech32(toAddress)

	// make this more dynamic if possible
	// Convert amount string to int64
	amountInt, err := sdk.ParseCoinNormalized(amount + denom)
	if err != nil {
		return "", err
	}
	msgToBroadcast := banktypes.NewMsgSend(fromAddressSdk, toAddressSdk, sdk.NewCoins(amountInt))
	err = txBuilder.SetMsgs(msgToBroadcast)
	if err != nil {
		return "", err
	}

	// Create a connection to the gRPC server.
	grpcConn, _ := grpc.Dial(
		"127.0.0.1:9090",    // Or your gRPC server address.
		grpc.WithInsecure(), // The Cosmos SDK doesn't support any transport security mechanism.
	)
	defer grpcConn.Close()

	txBuilder.SetGasLimit(2000000)
	txBuilder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("nhash", 38400000000)))
	// Get account number and sequence dynamically
	_, accSeq, _, err := GetAccountInfoWebAuthn(grpcConn, fromAddressSdk, encCfg.Codec)
	if err != nil {
		return "", err
	}

	accSeqs := []uint64{accSeq}
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return "", err
	}
	var sigsV2 []signing.SignatureV2
	sigsV2 = []signing.SignatureV2{}
	sigV2 := signing.SignatureV2{
		PubKey: nil,
		Data: &signing.SingleSignatureData{
			SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
			Signature: signatureBytes,
		},
		Sequence: accSeqs[0],
	}
	sigsV2 = append(sigsV2, sigV2)

	err = txBuilder.SetSignatures(sigsV2...)
	// Generated Protobuf-encoded bytes.
	txBytes, err := encCfg.TxConfig.TxEncoder()(txBuilder.GetTx())
	txSvcClient := txservice.NewServiceClient(grpcConn)
	clientCtx := context.Background()
	grpcRes, err := txSvcClient.BroadcastTx(
		clientCtx,
		&txservice.BroadcastTxRequest{
			Mode:    txservice.BroadcastMode_BROADCAST_MODE_SYNC,
			TxBytes: txBytes, // Proto-binary of the signed transaction, see previous step.
		},
	)
	if err != nil {
		return "", err
	}

	fmt.Println(grpcRes.TxResponse.Code) // Should be `0` if the tx is successful
	fmt.Printf("the tx hash is %s\n", grpcRes.TxResponse.TxHash)
	if grpcRes.TxResponse.Code != 0 {
		return "", fmt.Errorf("error broadcasting transaction: %s", grpcRes.TxResponse.RawLog)
	}
	return grpcRes.TxResponse.TxHash, nil
}
