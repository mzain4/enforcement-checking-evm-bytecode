"""Executable-bytecode identity after recognized compiler metadata removal."""
def executable(code):
    data = bytes.fromhex(code.removeprefix('0x'))
    while len(data) >= 3:
        size = int.from_bytes(data[-2:], 'big')
        if 0 < size < len(data) - 2:
            suffix = data[-2-size:-2]
            if (0xa0 <= suffix[0] <= 0xbf and any(k in suffix for k in (b'solc', b'ipfs', b'bzzr'))) or not any(suffix):
                data = data[:-2-size]
                continue
        break
    return data
