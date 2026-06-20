package badcreds

type Credentials struct {
	SecretAccessKey string // want "provider credential field must not use string"
	BearerToken     string // want "provider credential field must not use string"
	APIKey          string // want "provider credential field must not use string"
	ClientSecret    string // want "provider credential field must not use string"
	PublicHandle    string
}
