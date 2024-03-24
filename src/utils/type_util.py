def hexadecimal_to_binary_string(hexadecimal_str: str) -> str:
    as_int = int(hexadecimal_str, 16)

    as_binary_string_without_prefix = bin(as_int)[2:]

    # Fill with full 0 on the left to match the expected length
    expected_length = len(hexadecimal_str) * 4
    binary_string = as_binary_string_without_prefix.zfill(expected_length)

    return binary_string
