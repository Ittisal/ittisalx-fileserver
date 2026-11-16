# IttisalX FileServer

A small open-source file portal from IttisalX ([ittisal.com](https://ittisal.com)). Version 0.1.0. Python 3 standard library only, no database.

- **Files** page: upload (drag and drop), download, delete, browse folders.
- **Settings** page: change password, optional two-factor authentication (TOTP), upload/download size limits.

## Run

    ./run.sh      # start on port 8921 (set PORT=... to change)
    ./stop.sh     # stop

First install login: `admin` / `ittisalx`. You must change the password on first sign-in.

## Forgot the password?

On the server:

    ./reset-password.sh              # back to the default (ittisalx), 2FA turned off
    ./reset-password.sh MyNewPass1   # set a specific password (8+ characters)

## Files

- `upload/` - the files being served
- `config.json` - password hash, 2FA secret and limits (created on first run, keep private)
- `web/` - pages; `web/static/logo.svg` is the logo (replace it to rebrand)

## HTTPS (optional)

Plain HTTP is the default. To serve HTTPS, point to a certificate and key before starting:

    TLS_CERT=/path/fullchain.pem TLS_KEY=/path/privkey.pem ./run.sh

Or run behind a reverse proxy. Use HTTPS if the server is reachable beyond your network.

## License

GNU General Public License v3.0 or later (see `LICENSE`). You may use and modify it, but modified versions you distribute must stay open source under the same license.

Bundled: [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) (MIT) in `web/static/qrcode.js`. Logo and brand assets are IttisalX trademarks and are not covered by the GPL.
