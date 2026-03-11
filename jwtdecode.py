#!/usr/bin/env python3
"""jwtdecode - Decode JWT tokens. Zero deps."""
import sys,json,base64
def decode_part(s):
    s+='='*(4-len(s)%4);return json.loads(base64.urlsafe_b64decode(s))
def main():
    token=sys.argv[1] if len(sys.argv)>1 else input('JWT: ')
    parts=token.split('.')
    print('Header:');print(json.dumps(decode_part(parts[0]),indent=2))
    print('Payload:');print(json.dumps(decode_part(parts[1]),indent=2))
    import datetime
    payload=decode_part(parts[1])
    if 'exp' in payload:print(f'Expires: {datetime.datetime.fromtimestamp(payload["exp"])}')
    if 'iat' in payload:print(f'Issued:  {datetime.datetime.fromtimestamp(payload["iat"])}')
if __name__=='__main__':main()
