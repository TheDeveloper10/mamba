# TheDeveloper10/mamba

Package `TheDeveloper10/mamba` is a very basic wrapper of the package `github.com/golang-jwt/jwt/v4` that adds 
an optional encryption and decryption functionality using AES on top of it. It makes the work with JWT much easier!

## Install
With a [correctly configured](https://golang.org/doc/install#testing) Go toolchain:

```sh
go get -u github.com/TheDeveloper10/mamba@v1.0.0
```

## Examples
Create a signed token with no AES encryption:
```go
type User struct {
    ID   uint64 `json:"id"`
    Role uint   `json:"role"`
}

func main() {
	template := mamba.TokenTemplate{
		ExpiryTime: 360, // 5 minutes after issuing a token it will expire
		SigningKey: "your-signing key", // key which will be used to sign JWT 
	}

    // generate a new token using template
	token, err := mamba.NewToken[User](&template, &User{ ID: 1234, Role: 15 })
	if err != nil {
		panic(err.Error())
	}

	// print the generated JWT
	fmt.Println(token)
}
```

Create a signed and encrypted token that never expires:
```go
type User struct {
    ID   uint64 `json:"id"`
    Role uint   `json:"role"`
}

func main() {
	template := mamba.TokenTemplate{
		ExpiryTime: -1, // -1 = never expire
		SigningKey: "your-signing key", // key which will be used to sign JWT 
		EncryptionKey: "your-enc-key",
	}

    // generate a new token using template
	token, err := mamba.NewToken[User](&template, &User{ ID: 1234, Role: 15 })
	if err != nil {
		panic(err.Error())
	}

	// print the generated JWT
	fmt.Println(token)
}
```