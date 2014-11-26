type SHA interface {
	Digest(message []byte) []byte
}

type SHA1 struct{}

func (sha SHA1) digest(message []byte) []byte {

}
