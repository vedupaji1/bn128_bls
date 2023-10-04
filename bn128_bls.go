package bn128_bls

// Note: If You Are Looking For Simple BLS Signature Implementation, So CheckOut `go.dedis.ch/kyber/v3/sign/bls`
// This Package Is Only Developed To Generate KeyPairs And Perform BLS Signature Which Later Can Be Verified In Ethereum Smart Contract.

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"

	bn128PKG "github.com/arnaucube/go-snark/bn128"
)

type BLS struct {
	bn128          bn128PKG.Bn128
	privateKeySize int
}

type KeyPair struct {
	PrivateKey *big.Int
	PubKey     [3][2]*big.Int
	PubKeyG1   [3]*big.Int
}

func NewBls() *BLS {
	bn128, err := bn128PKG.NewBn128()
	if err != nil {
		log.Panic("Failed To Initialize BN128_BLS: ", err)
	}
	return &BLS{
		bn128:          bn128,
		privateKeySize: 256,
	}
}

func (bls *BLS) SetPrivateKeySize(newPrivateKeySize int) {
	bls.privateKeySize = newPrivateKeySize
}

func (bls *BLS) GenerateRandomKeyPair() (*KeyPair, error) {
	privateKey, err := rand.Prime(rand.Reader, bls.privateKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}
	pubKey := bls.bn128.G2.MulScalar(bls.bn128.G2.G, privateKey)
	pubKeyG1 := bls.bn128.G1.MulScalar(bls.bn128.G1.G, privateKey)
	return &KeyPair{
		PrivateKey: privateKey,
		PubKey:     pubKey,
		PubKeyG1:   pubKeyG1,
	}, nil
}

func (bls *BLS) NewKeyPair(privateKeyHexStr string) (*KeyPair, error) {
	privateKey, ok := new(big.Int).SetString(privateKeyHexStr, 16)
	if !ok {
		return nil, fmt.Errorf("invalid privateKeyHexStr")
	}
	pubKey := bls.bn128.G2.MulScalar(bls.bn128.G2.G, privateKey)
	pubKeyG1 := bls.bn128.G1.MulScalar(bls.bn128.G1.G, privateKey)
	return &KeyPair{
		PrivateKey: privateKey,
		PubKey:     pubKey,
		PubKeyG1:   pubKeyG1,
	}, nil
}

func (bls *BLS) ParsePubKey(pubKey [3][2]*big.Int) (res [4]*big.Int) {
	parsedPubKey := bls.bn128.G2.Affine(pubKey)
	res[0] = parsedPubKey[0][0]
	res[1] = parsedPubKey[0][1]
	res[2] = parsedPubKey[1][0]
	res[3] = parsedPubKey[1][1]
	return res
}

func (bls *BLS) ParsePubKeyG1(pubKeyG1 [3]*big.Int) [2]*big.Int {
	return bls.bn128.G1.Affine(pubKeyG1)
}

func (bls *BLS) ParsePubKeyG2(pubKeyG2 [3][2]*big.Int) [2][2]*big.Int {
	resData := bls.bn128.G2.Affine(pubKeyG2)
	return [2][2]*big.Int{resData[0], resData[1]}
}

// Perform HashToPoint Operation On Your Message And Obtained Two BigIntsHexStr, Pass Them In This Method.
// First HexStr: messageXHexStr
// Second HexStr: messageYHexStr
func (bls *BLS) GenerateSignature(keyPair *KeyPair, messageXHexStr string, messageYHexStr string) ([3]*big.Int, error) {
	messageX, ok := new(big.Int).SetString(messageXHexStr, 16)
	if !ok {
		return [3]*big.Int{}, fmt.Errorf("failed to generate messageX, invalid `messageXHexStr`")
	}
	messageY, ok := new(big.Int).SetString(messageYHexStr, 16)
	if !ok {
		return [3]*big.Int{}, fmt.Errorf("failed to generate messageY, invalid `messageYHexStr`")
	}
	messageG1 := bn128PKG.NewG1(bls.bn128.Fq1, [2]*big.Int{messageX, messageY})
	signature := bls.bn128.G1.MulScalar(messageG1.G, keyPair.PrivateKey)
	return signature, nil
}

func (bls *BLS) ParseSignature(signature [3]*big.Int) [2]*big.Int {
	return bls.bn128.G1.Affine(signature)
}

func (bls *BLS) VerifySignature(signature [3]*big.Int, signerPubKey [3][2]*big.Int, messageXHexStr string, messageYHexStr string) (bool, error) {
	messageX, ok := new(big.Int).SetString(messageXHexStr, 16)
	if !ok {
		return false, fmt.Errorf("failed to generate messageX, invalid `messageXHexStr`")
	}
	messageY, ok := new(big.Int).SetString(messageYHexStr, 16)
	if !ok {
		return false, fmt.Errorf("failed to generate messageY, invalid `messageYHexStr`")
	}
	messageG1 := bn128PKG.NewG1(bls.bn128.Fq1, [2]*big.Int{messageX, messageY})
	pair1 := bls.bn128.Pairing(messageG1.G, signerPubKey)
	pair2 := bls.bn128.Pairing(signature, bls.bn128.G2.G)
	return bls.bn128.Fq12.Equal(pair1, pair2), nil
}

func (bls *BLS) AggregatePubKeys(pubKeysG1 [][3]*big.Int, pubKeysG2 [][3][2]*big.Int) ([3]*big.Int, [3][2]*big.Int, error) {
	totalPubKeys := len(pubKeysG1)
	aggregatedG1 := [3]*big.Int{}
	aggregatedG2 := [3][2]*big.Int{}

	if totalPubKeys != len(pubKeysG2) {
		return aggregatedG1, aggregatedG2, fmt.Errorf("pubKeysG1 and pubKeysG2 must be same")
	}
	if totalPubKeys < 1 {
		return aggregatedG1, aggregatedG2, fmt.Errorf("zero pubKeysG1 and pubKeysG2 are passed")
	}
	if totalPubKeys < 2 {
		return pubKeysG1[0], pubKeysG2[0], nil
	}
	aggregatedG1 = pubKeysG1[0]
	aggregatedG2 = pubKeysG2[0]
	for i := 1; i < totalPubKeys; i++ {
		aggregatedG1 = bls.bn128.G1.Add(aggregatedG1, pubKeysG1[i])
		aggregatedG2 = bls.bn128.G2.Add(aggregatedG2, pubKeysG2[i])
	}
	return aggregatedG1, aggregatedG2, nil
}

func (bls *BLS) AggregateSignatures(signatures [][3]*big.Int) ([3]*big.Int, error) {
	totalSignatures := len(signatures)
	aggregatedSignature := [3]*big.Int{}
	if totalSignatures < 1 {
		return aggregatedSignature, fmt.Errorf("no signature have been passed")
	}
	if totalSignatures < 2 {
		return signatures[0], nil
	}
	aggregatedSignature = signatures[0]
	for i := 1; i < totalSignatures; i++ {
		aggregatedSignature = bls.bn128.G1.Add(aggregatedSignature, signatures[i])
	}
	return aggregatedSignature, nil
}

func (bls *BLS) NewG1(g1 [2]*big.Int) [3]*big.Int {
	return bn128PKG.NewG1(bls.bn128.Fq1, g1).G
}

func (bls *BLS) NewG2(g2 [2][2]*big.Int) [3][2]*big.Int {
	return bn128PKG.NewG2(bls.bn128.Fq2, g2).G
}
