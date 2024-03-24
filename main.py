import pickle
import time
from queue import Queue, Empty
from threading import Thread, Event
from typing import Dict
from scapy.all import sniff
from scapy.layers.inet import TCP
from src.classes.dofus_network_message_class import DofusNetworkMessage
from src.classes.enums.packet_direction_enum import PacketDirectionEnum
from src.classes.tcp_packet_class import TcpPacket
from src.utils.type_util import hexadecimal_to_binary_string


with open("dofus.protocol", "rb") as file:
    PROTOCOL = pickle.load(file)

SERVER_PORT = 5555


def tcp_packet_processing(
        protocol: Dict[str, any],
        tcp_packet_queue: Queue,
        dofus_network_message_queue: Queue,
        packet_direction: PacketDirectionEnum,
        stop_event: Event
):
    payload_binary_string_buffer = ""

    while True:

        if stop_event.is_set():
            break

        try:
            tcp_packet: TcpPacket = tcp_packet_queue.get(block=True, timeout=1)
        except Empty:
            continue

        if tcp_packet.payload is None:
            continue

        payload_binary_string_buffer += hexadecimal_to_binary_string(tcp_packet.payload)

        dofus_network_message = DofusNetworkMessage(tcp_packet.timestamp, packet_direction)

        extraction_complete, payload_binary_string_buffer = dofus_network_message.extract_header(payload_binary_string_buffer, protocol)
        if extraction_complete is False:
            continue
        else:
            if dofus_network_message.associated_class is None:
                payload_binary_string_buffer = ""
                print("\033[91m----------------------------------------------------------------\n"
                      "TCP packet discarded\n"
                      "----------------------------------------------------------------")
                continue

        if packet_direction == PacketDirectionEnum.CLIENT_SERVER:
            payload_binary_string_buffer = payload_binary_string_buffer[32:]

        extraction_complete, payload_binary_string_buffer = dofus_network_message.extract_size(payload_binary_string_buffer)
        if extraction_complete is False:
            continue

        extraction_complete, payload_binary_string_buffer = dofus_network_message.extract_data(payload_binary_string_buffer)
        if extraction_complete is False:
            continue

        if len(payload_binary_string_buffer) == 0:
            dofus_network_message.raw_payload = tcp_packet.payload

        dofus_network_message_queue.put(dofus_network_message)

    print(f'Tcp packet processing ({packet_direction.value.lower()}) thread stopped')


def tcp_sniffer(tcp_packet_queue: Queue, packet_direction: PacketDirectionEnum, stop_event: Event):
    def packet_callback(packet):
        if packet.haslayer(TCP):
            packet = TcpPacket(packet)
            if (packet_direction == PacketDirectionEnum.CLIENT_SERVER) and (packet.port_dst == SERVER_PORT):
                tcp_packet_queue.put(packet)
            elif (packet_direction == PacketDirectionEnum.SERVER_CLIENT) and (packet.port_src == SERVER_PORT):
                tcp_packet_queue.put(packet)

        if stop_event.is_set():
            return

    sniff(
        filter=f'tcp and port {SERVER_PORT}',
        prn=packet_callback,
        stop_filter=lambda x: stop_event.is_set()
    )

    print(f'Tcp sniffer ({packet_direction.value.lower()}) thread stopped')


def main():
    dofus_network_message_queue = Queue()

    tcp_client_server_queue = Queue()
    tcp_server_client_queue = Queue()

    stop_event = Event()

    tcp_sniff_client_server_thread = Thread(
        target=tcp_sniffer,
        args=[tcp_client_server_queue, PacketDirectionEnum.CLIENT_SERVER, stop_event]
    )
    tcp_sniff_client_server_thread.start()

    tcp_packet_processing_client_server_thread = Thread(
        target=tcp_packet_processing,
        args=[PROTOCOL, tcp_client_server_queue, dofus_network_message_queue, PacketDirectionEnum.CLIENT_SERVER, stop_event]
    )
    tcp_packet_processing_client_server_thread.start()

    tcp_sniff_server_client_thread = Thread(
        target=tcp_sniffer,
        args=[tcp_server_client_queue, PacketDirectionEnum.SERVER_CLIENT, stop_event]
    )
    tcp_sniff_server_client_thread.start()

    tcp_packet_processing_server_client_thread = Thread(
        target=tcp_packet_processing,
        args=[PROTOCOL, tcp_server_client_queue, dofus_network_message_queue, PacketDirectionEnum.SERVER_CLIENT, stop_event]
    )
    tcp_packet_processing_server_client_thread.start()

    start_timestamp = time.time()

    while True:

        try:
            dofus_network_message: DofusNetworkMessage = dofus_network_message_queue.get(block=True, timeout=None)

            print_color = '\033[92m' if dofus_network_message.packet_direction == PacketDirectionEnum.CLIENT_SERVER else '\033[94m'

            print(
                f'{print_color}[{round(dofus_network_message.timestamp - start_timestamp, 4)}] {dofus_network_message.packet_direction.value} - {dofus_network_message.associated_class} - {dofus_network_message.data}'
            )

            if dofus_network_message.raw_payload is not None:
                print(f'Raw payload: {dofus_network_message.raw_payload}')

        except KeyboardInterrupt:
            stop_event.set()
            break

    tcp_sniff_client_server_thread.join()
    tcp_packet_processing_client_server_thread.join()
    tcp_sniff_server_client_thread.join()
    tcp_packet_processing_server_client_thread.join()


if __name__ == "__main__":
    main()
