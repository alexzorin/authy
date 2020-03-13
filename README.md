# authy


[![GoDoc](https://godoc.org/github.com/alexzorin/authy?status.svg)](https://godoc.org/github.com/alexzorin/authy)

This is a Go library that allows you to access your [Authy](https://authy.com) TOTP tokens.

It was created to facilitate exports of your TOTP database, because Authy do not provide any way to access or port your TOTP tokens to another client.

It also somewhat documents Authy's protocol/encryption, since public materials on that are somewhat scarce.

Please be careful. You can get your Authy account suspended very easily by using this package. It does not hide itself or mimic the official clients.

## Applications

### authy-export
This program will enrol itself as an additional device on your Authy account and export all of your TOTP tokens in [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

**Installation**

Of course, `go` must be installed and set up, with `$GOPATH/bin` in your `$PATH`.

Go 1.12 or higher is required. If you have a version lower than 1.12, first install 1.12 by doing.

1. `go get golang.org/dl/go1.12.7`
2. `go1.12.7 download`

Then, in the following instructions, replace `go` with `go1.12.7`.

Next, install `authy-export` by running `go get github.com/alexzorin/authy/cmd/authy-export`.

**To use it:**

1. Run `authy-export`
2. The program will prompt you for your phone number country code (e.g. 1 for United States) and your phone number. This is the number that you used to register your Authy account originally.
3. If the program identifies an existing Authy account, it will send a device registration request using the `push` method. This will send a push notification to your existing Authy apps (be it on Android, iOS, Desktop or Chrome), and you will need to respond that from your other app(s).
4. If the device registration is successful, the program will save its authentication credential (a random value) to `$HOME/authy-go.json` for further uses. **Make sure to delete this file and de-register the device after you're finished.**
5. If the program is able to fetch your TOTP encrypted database, it will prompt you for your Authy backup password. This is required to decrypt the TOTP secrets for the next step. 
6. The program will dump all of your TOTP tokens in URI format, which you can use to import to other applications.

If you [notice any missing TOTP tokens](https://github.com/alexzorin/authy/issues/1#issuecomment-516187701), please try toggling "Authenticator Backups" in your Authy settings, to force your backup to be resynchronized.

**How do you then import it into another app?**

Up to you, depends on the app. If the app uses QR scanning, you can try stick all the dumped URIs into a file (`tokens`) and then scan each QR code from your terminal, e.g.:

```bash
#!/usr/bin/env bash
cat tokens | while IFS= read -r line; do
  clear
  echo -n "$line" | qrencode -t UTF8
  read -p $"Press any key to continue" key < /dev/tty
done
```

## LICENSE

Copyright Alex Zorin 2019

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

All product names, logos, and brands are property of their respective owners. All company, product and service names used in this website are for identification purposes only. Use of these names, logos, and brands does not imply endorsement
