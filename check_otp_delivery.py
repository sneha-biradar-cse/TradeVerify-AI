"""
Sends ONE test message so you can see whether email / SMS / WhatsApp delivery works BEFORE you start the server.

  python check_otp_delivery.py email    you@gmail.com
  python check_otp_delivery.py sms      +919876543210
  python check_otp_delivery.py whatsapp +919876543210
  python check_otp_delivery.py status                      (shows what is configured)

Settings come from otp_settings.env (the same file the server reads).
"""
import sys

import env_loader  # noqa: F401  (reads otp_settings.env)
import otp_delivery


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == 'status':
        ch = otp_delivery.configured_channels()
        print('Configured channels:', ', '.join(ch) if ch else 'NONE (fill in otp_settings.env)')
        return 0 if ch else 1
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    try:
        print('OK:', otp_delivery.send_test(sys.argv[1], sys.argv[2]))
        return 0
    except Exception as e:
        print('FAILED:', e)
        msg = str(e).lower()
        if 'authentication' in msg or '535' in msg:
            print('Hint (email): the mail server refused the login. Gmail needs 2-Step Verification ON and a 16-character App Password.')
        if 'unverified' in msg or 'trial' in msg:
            print('Hint (SMS): a Twilio trial account can only message numbers you have verified in the Twilio console.')
        return 2


if __name__ == '__main__':
    sys.exit(main())
