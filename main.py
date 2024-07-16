import argparse
import json
import gCrypto


def decrypt_data(data_enc: bytes, iv: bytes, aes_key: bytes, pad: bool) -> bytes:
    gCrypto.AES_CBC.decrypt(data_enc, aes_key, iv, pad)
    return gCrypto.AES_CBC.decrypt(data_enc, aes_key, iv, pad)


def decrypt_file(args: argparse.Namespace, conf: dict) -> None:
    aes_filename: str = conf['aes_filename']
    frame_len: int = conf['frame_len']
    enc_start_pos: int = conf['enc_start_pos']
    enc_len: int = conf['enc_len']
    iv_pos: int = conf['iv_pos']

    with open(aes_filename, 'rb') as file:
        aes_key: bytes = file.read()

    with open(args.infile, 'rb') as infile, open(args.outfile, 'wb') as outfile:
        while True:
            raw = infile.read(frame_len)
            if len(raw) == 0:
                break
            if len(raw) != frame_len:
                raise Exception(f"Incomplete frame. frame_size={len(raw)}")
            data_enc = raw[enc_start_pos:enc_start_pos + enc_len]
            iv = raw[iv_pos:iv_pos + 16]
            ###
            # data_enc = gCrypto.AES_CBC.encrypt(data_enc, aes_key, iv, False)
            ###
            data = gCrypto.AES_CBC.decrypt(data_enc, aes_key, iv, False)
            new_raw = raw[0:enc_start_pos] + data + iv
            outfile.write(new_raw)


def dump_file(args: argparse.Namespace, conf: dict) -> None:
    aes_filename: str = conf['aes_filename']
    frame_len: int = conf['frame_len']
    enc_start_pos: int = conf['enc_start_pos']
    enc_len: int = conf['enc_len']
    iv_pos: int = conf['iv_pos']

    with open(aes_filename, 'rb') as file:
        aes_key: bytes = file.read()

    with open(args.infile, 'rb') as infile:
        while True:
            raw = infile.read(frame_len)
            if len(raw) == 0:
                break
            if len(raw) != frame_len:
                raise Exception(f"Incomplete frame. frame_size={len(raw)}")
            data_enc = raw[enc_start_pos:enc_start_pos + enc_len]
            iv = raw[iv_pos:iv_pos + 16]
            data = gCrypto.AES_CBC.decrypt(data_enc, aes_key, iv, False)
            new_raw = raw[0:enc_start_pos] + data + iv
            print(new_raw)


def main():
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description='file parser description')
    parser.add_argument('--action', '-a', choices=["decrypt", "dump"],
                        type=str, help='action', required=True)
    parser.add_argument('--conf', '-c', type=str, help='Conf filename', default='conf.json')

    parser.add_argument('--type', type=int, help='Type', choices=[0, 1], default=0)
    parser.add_argument('--infile', type=str, help='infile')
    parser.add_argument('--outfile', type=str, help='outfile')

    args: argparse.Namespace = parser.parse_args()

    conf_filename: str = args.conf
    with open(conf_filename, 'r') as file:
        conf: dict = json.load(file)

    action: str = args.action
    if action == 'decrypt':
        decrypt_file(args, conf)

    elif action == 'dump':
        dump_file(args, conf)

    else:
        raise Exception(f"Unknown action: '{action}'")


if __name__ == '__main__':
    main()
