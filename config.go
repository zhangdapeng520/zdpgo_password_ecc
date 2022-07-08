package zdpgo_password_ecc

// Config 密码配置对象
type Config struct {
	KeyPath            string `yaml:"key_path" json:"key_path"`
	PrivateKey         []byte `yaml:"private_key" json:"private_key"`
	PublicKey          []byte `yaml:"public_key" json:"public_key"`
	PrivateKeyPrefix   string `yaml:"private_key_prefix" json:"private_key_prefix"`
	PublicKeyPrefix    string `yaml:"public_key_prefix" json:"public_key_prefix"`
	PrivateKeyFileName string `yaml:"private_key_file_name" json:"private_key_file_name"`
	PublicKeyFileName  string `yaml:"public_key_file_name" json:"public_key_file_name"`
}
