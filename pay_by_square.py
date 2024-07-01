from typing import cast, Optional, Union

import lzma
import binascii
from datetime import datetime, date
import argparse


def generate(
    *,
    amount: float,
    iban: str,
    swift: str = '',
    date: Optional[date] = None,
    beneficiary_name: str = '',
    currency: str = 'EUR',
    variable_symbol: str = '',
    constant_symbol: str = '',
    specific_symbol: str = '',
    note: str = '',
    beneficiary_address_1: str = '',
    beneficiary_address_2: str = '',
    **kwds
) -> str:
    '''Generate pay-by-square code that can by used to create QR code for
    banking apps

    When date is not provided current date will be used.
    '''

    if date is None:
        date = datetime.now()

    # 1) create the basic data structure
    data = '\t'.join(
        [
            '',
            '1',  # payment
            '1',  # simple payment
            f'{amount:.2f}',
            currency,
            date.strftime('%Y%m%d'),
            variable_symbol,
            constant_symbol,
            specific_symbol,
            '',  # previous 3 entries in SEPA format, empty because already provided above
            note,
            '1',  # to an account
            iban,
            swift,
            '0',  # not recurring
            '0',  # not 'inkaso'
            beneficiary_name,
            beneficiary_address_1,
            beneficiary_address_2,
        ]
    )

    # 2) Add a crc32 checksum
    checksum = binascii.crc32(data.encode()).to_bytes(4, 'little')
    total = checksum + data.encode()

    # 3) Run through XZ
    compressed = lzma.compress(
        total,
        format=lzma.FORMAT_RAW,
        filters=[
            {
                'id': lzma.FILTER_LZMA1,
                'lc': 3,
                'lp': 0,
                'pb': 2,
                'dict_size': 128 * 1024,
            }
        ],
    )

    # 4) prepend length
    compressed_with_length = b'\x00\x00' + len(total).to_bytes(2, 'little') + compressed

    # 5) Convert to binary string
    binary = ''.join(
        [bin(single_byte)[2:].zfill(8) for single_byte in compressed_with_length]
    )

    # 6) Pad with zeros on the right up to a multiple of 5
    length = len(binary)
    remainder = length % 5
    if remainder:
        binary += '0' * (5 - remainder)
        length += 5 - remainder

    # 7) Substitute each quintet of bits with corresponding character
    subst = '0123456789ABCDEFGHIJKLMNOPQRSTUV'
    return ''.join(
        [subst[int(binary[5 * i : 5 * i + 5], 2)] for i in range(length // 5)]
    )

def decode(pbs: str):
    # 7) Back-substitute each character for to a quintet of bits
    subst = '0123456789ABCDEFGHIJKLMNOPQRSTUV'
    binary = str.encode(''.join([bin(subst.find(c))[2:].zfill(5) for c in pbs]), 'utf-8')

    # 6) Remove padding
    l = (len(binary) // 8) * 8
    binary_no_pad = binary[0:l]

    # 5) Decode binary
    bdata = int(binary_no_pad, 2).to_bytes(l // 8, 'big')

    # 4) Remove header, read length
    bheader = bdata[0:2]
    blength = bdata[2:4]
    compressed = bdata[4:]
    assert bheader == b'\x00\x00'
    length = int.from_bytes(blength, 'little')

    # 3) Decompress XZ
    decompressor = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[
            {
                'id': lzma.FILTER_LZMA1,
                'lc': 3,
                'lp': 0,
                'pb': 2,
                'dict_size': 128 * 1024,
            }
        ])

    total = decompressor.decompress(compressed, max_length=length)

    # 2) Check crc32
    checksum = total[0:4]
    data = total[4:]
    assert checksum == binascii.crc32(data).to_bytes(4, 'little')

    # 1) Split data
    split_data = data.decode('utf-8').split('\t')

    res = {}
    assert split_data[0] in ['', ' ']
    assert split_data[1] == '1' # payment
    assert split_data[2] == '1' # simple payment
    res['amount'] = split_data[3]
    res['currency'] = split_data[4]
    res['date'] = split_data[5]
    res['variable_symbol'] = split_data[6]
    res['constant_symbol'] = split_data[7]
    res['specific_symbol'] = split_data[8]
    assert split_data[9] == '' # previous 3 entries in SEPA format, empty because already provided above
    res['note'] = split_data[10]
    assert split_data[11] == '1'
    res['iban'] = split_data[12]
    res['swift'] = split_data[13]
    res['recurring'] = split_data[14]
    assert split_data[15] == '0'  # not 'inkaso'
    res['inkaso'] = split_data[15]
    try:
        res['beneficiary_name'] = split_data[16]
        res['beneficiary_address_1'] = split_data[17]
        res['beneficiary_address_2'] = split_data[18]
    except IndexError:
        pass  # Optional fields
    return res


class ArgsEncode:
    qrcode: bool
    amount: float
    iban: str
    swift: str = ''
    date: Optional[date] = None
    beneficiary_name: str = ''
    currency: str = 'EUR'
    variable_symbol: str = ''
    constant_symbol: str = ''
    specific_symbol: str = ''
    note: str = ''
    beneficiary_address_1: str = ''
    beneficiary_address_2: str = ''


class ArgsDecode:
    code: str


# Note: also has func(Args..)
ArgsType = Union[ArgsEncode, ArgsDecode]


def generator(args: ArgsEncode):
    gen_qrcode = args.qrcode
    code = generate(**vars(args))
    print(code)
    if gen_qrcode:
        try:
            import qrcode
        except ImportError:
            raise SystemExit('Install python \'qrcode\' module show qr-code')
        img = qrcode.make(code)
        img.show()


def decoder(args: ArgsDecode):
    kv = decode(args.code)
    print(kv)


def get_args() -> ArgsEncode:
    parser = argparse.ArgumentParser(
            description=('Pay-by-square encoder and decoder.'
                         'Implements non-recurring simple payment.'))
    subparsers = parser.add_subparsers(help='sub-command help')

    # encode
    parser_encode = subparsers.add_parser('encode', help='Encode a pay-by-square payment')
    parser_encode.add_argument('--amount', type=float)
    parser_encode.add_argument('--iban', type=str)
    parser_encode.add_argument('--swift', type=str, default='')
    parser_encode.add_argument('--date', type=str) # TODO: Optional[date]
    parser_encode.add_argument('--beneficiary_name', type=str, default='')
    parser_encode.add_argument('--currency', type=str, default='EUR')
    parser_encode.add_argument('--variable_symbol', type=str, default='')
    parser_encode.add_argument('--constant_symbol', type=str, default='')
    parser_encode.add_argument('--specific_symbol', type=str, default='')
    parser_encode.add_argument('--note', type=str, default='')
    parser_encode.add_argument('--beneficiary_address_1', type=str, default='')
    parser_encode.add_argument('--beneficiary_address_2', type=str, default='')
    parser_encode.add_argument('--qrcode', '-q', action='store_true', help='Generate and display qr-code')
    parser_encode.set_defaults(func=generator)

    # decode
    parser_decode = subparsers.add_parser('decode', help='Decode a pay-by-square payment')
    parser_decode.add_argument('code', type=str, help='Payment string, e.g. output from a qr-code-scanner')
    parser_decode.set_defaults(func=decoder)

    args1 = parser.parse_args()
    args = cast(ArgsType, args1)
    return args1


def gen_sample(args: ArgsEncode) -> None:
    args = ArgsType()
    args.qrcode = True
    args.amount=1
    args.iban='SK7700000000000000000000'
    args.swift='FIOZSKBAXXX'
    args.variable_symbol='11'
    args.constant_symbol='22'
    args.specific_symbol='33'
    args.beneficiary_name='Foo'
    args.beneficiary_address_1='address 1'
    args.beneficiary_address_2='address 2'
    args.note='bar'
    generate(args)


def main() -> None:
    args = get_args()
    args.func(args)


if __name__ == '__main__':
    main()
