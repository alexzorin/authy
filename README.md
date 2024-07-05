# authy

> [!CAUTION]
> As of July 2024, this project is abandoned and no longer functional. Owing to [this incident](https://www.macrumors.com/2024/07/05/authy-app-hack-exposes-phone-numbers/), Authy added some attestation requirements to their API [which affects this project](https://github.com/alexzorin/authy/issues/33). Since the desktop app and browser extensions are deprecated and I have no personal motivation to reverse engineer their mobile apps, I am archiving this project. Anybody who is interested in becoming the maintainer is free to fork this project and I can redirect this repository to them.

-----

[![GoDoc](https://godoc.org/github.com/alexzorin/authy?status.svg)](https://godoc.org/github.com/alexzorin/authy)

This is a Go library that allows you to access your [Authy](https://authy.com) TOTP tokens.

It was created to facilitate exports of your TOTP database, because Authy do not provide any way to access or port your TOTP tokens to another client.

It also somewhat documents Authy's protocol/encryption, since public materials on that are somewhat scarce.

Please be careful. You can get your Authy account suspended very easily by using this package. It does not hide itself or mimic the official clients.

## Applications

### authy-export
This program will enrol itself as an additional device on your Authy account and export all of your TOTP tokens in [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format).

It is also able to save the TOTP database in a JSON file encrypted with your Authy backup password, which can be used for backup purposes, and to read it back in order to decrypt it.

**Installation**

Pre-built binaries are available from the [releases page](https://github.com/alexzorin/authy/releases). (Windows binaries have been removed because of continual false positive virus complaints, sorry).

Alternatively, it can be compiled from source, which requires [Go 1.12 or newer](https://golang.org/doc/install):

```shell
go install github.com/alexzorin/authy/...@latest
```

**To use it:**

1. Run `authy-export`
2. The program will prompt you for your phone number country code (e.g. 1 for United States) and your phone number. This is the number that you used to register your Authy account originally.
3. If the program identifies an existing Authy account, it will send a device registration request using the `push` method. This will send a push notification to your existing Authy apps (be it on Android, iOS, Desktop or Chrome), and you will need to respond that from your other app(s).
4. If the device registration is successful, the program will save its authentication credential (a random value) to `$HOME/authy-go.json` for further uses. **Make sure to delete this file and de-register the device after you're finished.**
5. If the program is able to fetch your TOTP encrypted database, it will prompt you for your Authy backup password. This is required to decrypt the TOTP secrets for the next step. 
6. The program will dump all of your TOTP tokens in URI format, which you can use to import to other applications.
7. Alternatively, you can save the TOTP encrypted database to a file with the `--save` option, and reload it later with the `--load` option in order to decrypt it and dump the tokens.

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

**"My Twitch (or other site) token is different to the one I see in the Authy app?"**

This is expected, depending on what the site is. 

In Authy, there are two types of secrets:

- **Tokens**: You sign up to a website, the website generates a TOTP secret, and you scan it via a QR code (in *any* app, not necessarily Authy). You can export that secret to other TOTP apps and the code will match.
- **Apps**: The website has exported their TOTP flow to Authy's proprietary service, which requires you to use the Authy app. For sites like Twitch, Authy assigns a unique TOTP secret for every device you use the Authy app on. Each device will produce different 7-digit codes, but they will all work. If you deregister any device from your Authy account, that device's TOTP secrets will be revoked and its 7-digit codes will no longer work.

Twitch (and a handful of other sites) are the latter: Authy Apps.

Now, `authy-export` registers itself as a device on your Authy account. Per the explanation above, that means it is assigned a unique TOTP secret for sites like Twitch, which means it will generate different 7-digit codes to your primary Authy device. These codes will work as long as you don't deregister the `authy-export` device from your Authy account.

This is unfortunate, but the fact is: you cannot fully delete your Authy account if you want to keep using TOTP-based authentication with Twitch. If you do, all of the TOTP secrets will be revoked, and you will locked out of Twitch. It happened to me, and Twitch support chose to not help me out ^_^.

**Batch support**

When environment variable named `AUTHY_EXPORT_PASSWORD` exists, `authy-export` does not ask for a password and uses the variable instead. Use with care!

## LICENSE

See [LICENSE](LICENSE)

## Trademark Legal Notice

All product names, logos, and brands are property of their respective owners. All company, product and service names used in this website are for identification purposes only. Use of these names, logos, and brands does not imply endorsement
