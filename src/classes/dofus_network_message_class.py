from src.classes.enums.packet_direction_enum import PacketDirectionEnum


class DofusNetworkMessage:

    MESSAGE_ID_BITS = 14
    SIZE_LENGTH_BITS = 2
    BITS_PER_BYTE = 8

    def __init__(self, timestamp: float, packet_direction: PacketDirectionEnum):
        self.timestamp = timestamp
        self.packet_direction = packet_direction
        self.id = None
        self.associated_class = None
        self.size_length = None
        self.size = None
        self.data = None
        self.raw_payload = None

    def extract_header(self, payload_bin: str, protocol: dict) -> tuple[bool, str]:
        min_header_length = DofusNetworkMessage.MESSAGE_ID_BITS + DofusNetworkMessage.SIZE_LENGTH_BITS
        if len(payload_bin) < min_header_length:
            return False, payload_bin

        self.id = int(payload_bin[:DofusNetworkMessage.MESSAGE_ID_BITS], 2)
        self.get_associated_class(protocol)

        self.size_length = int(payload_bin[DofusNetworkMessage.MESSAGE_ID_BITS:
                                           DofusNetworkMessage.MESSAGE_ID_BITS + DofusNetworkMessage.SIZE_LENGTH_BITS], 2)

        return True, payload_bin[min_header_length:]

    def extract_size(self, payload_bin: str) -> tuple[bool, str]:
        size_bits = self.size_length * DofusNetworkMessage.BITS_PER_BYTE
        if len(payload_bin) < size_bits:
            return False, payload_bin

        if self.size_length > 0:
            self.size = int(payload_bin[:size_bits], 2)
            return True, payload_bin[size_bits:]
        else:
            self.size = 0
            return True, payload_bin

    def extract_data(self, payload_bin: str) -> tuple[bool, str]:
        data_bits = self.size * DofusNetworkMessage.BITS_PER_BYTE
        if len(payload_bin) < data_bits:
            return False, payload_bin

        if self.size > 0:
            data_hex = hex(int(payload_bin[:data_bits], 2))[2:]
            self.data = ' '.join(data_hex[i:i+2] for i in range(0, len(data_hex), 2))
            return True, payload_bin[data_bits:]
        else:
            self.data = ""
            return True, payload_bin

    def get_associated_class(self, protocol: dict):
        associated_class = protocol.get(str(self.id))
        if associated_class:
            self.associated_class = associated_class.replace(".as", "")
        else:
            self.associated_class = None
            print(f'Unknown message ID: {self.id}')
