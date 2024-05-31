def newFpElement(x *big.Int) fp.Element : pass
def NewG1Point(x, y *big.Int) *G1Point : pass
def NewZeroG1Point() *G1Point : pass
def (p *G1Point) Add(p2 *G1Point) *G1Point : pass
def (p *G1Point) Sub(p2 *G1Point) *G1Point : pass
def (p *G1Point) VerifyEquivalence(p2 *G2Point) (bool, error) : pass
def (p *G1Point) Serialize() []byte : pass
def (p *G1Point) Deserialize(data []byte) *G1Point : pass
def NewG2Point(X, Y [2]*big.Int) *G2Point : pass
def NewZeroG2Point() *G2Point : pass
def (p *G2Point) Add(p2 *G2Point) *G2Point : pass
def (p *G2Point) Sub(p2 *G2Point) *G2Point : pass
def (p *G2Point) Serialize() []byte : pass
def (p *G2Point) Deserialize(data []byte) *G2Point : pass
def NewZeroSignature() *Signature : pass
def (s *Signature) Add(otherS *Signature) *Signature : pass
def (s *Signature) Verify(pubkey *G2Point, message [32]byte) (bool, error) : pass
def NewPrivateKey(sk string) (*PrivateKey, error) : pass
def NewKeyPair(sk *PrivateKey) *KeyPair : pass
def NewKeyPairFromString(sk string) (*KeyPair, error) : pass
def GenRandomBlsKeys() (*KeyPair, error) : pass
def (k *KeyPair) SaveToFile(path string, password string) error : pass
def ReadPrivateKeyFromFile(path string, password string) (*KeyPair, error) : pass
def (k *KeyPair) SignMessage(message [32]byte) *Signature : pass
def (k *KeyPair) SignHashedToCurveMessage(g1HashedMsg *bn254.G1Affine) *Signature : pass
def (k *KeyPair) GetPubKeyG2() *G2Point : pass
def (k *KeyPair) GetPubKeyG1() *G1Point : pass
