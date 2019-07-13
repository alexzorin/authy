# authy


[![GoDoc](https://godoc.org/github.com/alexzorin/authy?status.svg)](github.com/alexzorin/authy)

This is a Go library that allows you to access your [Authy](https://authy.com) TOTP tokens.

It was created to facilitate exports of your TOTP database, because Authy do not provide any way to access or port your TOTP tokens to another client.

It also somewhat documents Authy's protocol/encryption, since public materials on that are somewhat scarce.

Please be careful. You can get your Authy account suspended very easily by using this package. It does not hide itself or mimic the official clients.

## Applications

### authy-export
This program will enrol itself as an additional device on your Authy account and export all of your TOTP tokens in [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

To use it:

1. Run `authy-export`
2. The program will prompt you for your phone number country code (e.g. 1 for United States) and your phone number. This is the number that you used to register your Authy account originally.
3. If the program identifies an existing Authy account, it will send a device registration request using the `push` method. This will send a push notification to your existing Authy apps (be it on Android, iOS, Desktop or Chrome), and you will need to respond that from your other app(s).
4. If the device registration is successful, the program will save its authentication credential (a random value) to `$HOME/authy-go.json` for further uses. **Make sure to delete this file and de-register the device after you're finished.**
5. If the program is able to fetch your TOTP encrypted database, it will prompt you for your Authy backup password. This is required to decrypt the TOTP secrets for the next step. 
6. The program will dump all of your TOTP tokens in URI format, which you can use to import to other applications.