"""
Readable fast packet sniffer (no OOP, descriptive names).

- Uses a background writer thread to keep packet callback very small.
- Writes newline-delimited JSON so each packet is available immediately.
- Uses argparse for friendly command-line arguments (no direct sys.argv use).
- Avoids f-strings and .format() placeholders; uses simple string concatenation.
"""

from scapy.all import sniff
import threading
import queue
import json
import logging
import time
import argparse

# ----- Configuration defaults ----- #
DEFAULT_OUTPUT_FILE = "packets.ndjson"        # output NDJSON file
DEFAULT_LOG_FILE = "packet_sniffer.log"       # text log file
DEFAULT_QUEUE_MAX_SIZE = 10000                # maximum packets queued
DEFAULT_PRINT_EVERY_N = 1                     # how often to print console line

# ----- Logging setup ----- #
logger = logging.getLogger("packet_sniffer")  # logger name
logger.setLevel(logging.INFO)                  # logging level
file_handler = logging.FileHandler(DEFAULT_LOG_FILE, mode="a")  # append to file
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
logger.addHandler(file_handler)

# ----- Shared objects ----- #
packet_queue = queue.Queue(maxsize=DEFAULT_QUEUE_MAX_SIZE)  # queue for writer
writer_stop_signal = threading.Event()                      # signal writer to stop

# ----- Writer thread function ----- #
def writer_loop(output_path):
    """
    Background loop that writes packet dictionaries to a file as NDJSON
    and logs a compact message to the log file.
    """
    # open file in append mode so partial captures are preserved
    out_file = open(output_path, "a", encoding="utf-8")
    try:
        # run until stop signal and queue empty
        while not writer_stop_signal.is_set() or not packet_queue.empty():
            try:
                # wait briefly for a packet, raise queue.Empty if none
                packet_record = packet_queue.get(timeout=0.2)
            except queue.Empty:
                # no packet available; loop again
                continue

            # sentinel to indicate shutdown
            if packet_record is None:
                packet_queue.task_done()
                break

            # write JSON line and flush for immediate availability
            out_file.write(json.dumps(packet_record, ensure_ascii=False) + "\n")
            out_file.flush()

            # small log entry using concatenation
            log_message = "Packet recorded: src=" + str(packet_record.get("src")) + " dst=" + str(packet_record.get("dst"))
            logger.info(log_message)

            packet_queue.task_done()
    finally:
        out_file.close()

# ----- Packet callback (must be tiny) ----- #
packet_counter = 0                       # total packets captured (global)
print_lock = threading.Lock()            # guard console prints

def fast_packet_callback(packet):
    """
    Very small callback executed in sniffing thread.
    Collects only a few lightweight fields and queues them.
    """
    global packet_counter

    # minimal extraction to avoid heavy operations in callback
    record = {
        "timestamp": time.time(),                       # epoch time
        "src": getattr(packet, "src", None),            # source IP if present
        "dst": getattr(packet, "dst", None)             # destination IP if present
    }

    # add ports if present (lightweight getattr)
    source_port = getattr(packet, "sport", None)
    dest_port = getattr(packet, "dport", None)
    if source_port is not None:
        record["sport"] = source_port
    if dest_port is not None:
        record["dport"] = dest_port

    # protocol name if available (keeps things descriptive)
    protocol_name = packet.name if hasattr(packet, "name") else None
    if protocol_name is not None:
        record["proto"] = protocol_name

    # try to enqueue without blocking capture thread
    try:
        packet_queue.put_nowait(record)
    except queue.Full:
        # drop packet if queue full; keep capture fast
        drop_message = "Packet queue full; dropping packet from " + str(record.get("src")) + " to " + str(record.get("dst"))
        logger.warning(drop_message)
        return

    # throttled console feedback (convert to str explicitly)
    packet_counter += 1
    if DEFAULT_PRINT_EVERY_N > 0:
        if packet_counter % DEFAULT_PRINT_EVERY_N == 0:
            with print_lock:
                console_message = "Captured packet number " + str(packet_counter) + " src: " + str(record.get("src")) + " dst: " + str(record.get("dst"))
                print(console_message)

# ----- Argument parsing ----- #
def parse_command_line_arguments():
    """Build and return parsed CLI arguments with descriptive names."""
    parser = argparse.ArgumentParser(description="Fast packet sniffer with background writer.")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff on (omit to sniff all).")
    parser.add_argument("--max-packets", "-c", type=int, default=0, help="Stop after this many packets (0 means unlimited).")
    parser.add_argument("--output-file", "-o", default=DEFAULT_OUTPUT_FILE, help="Path to NDJSON output file.")
    parser.add_argument("--log-file", "-l", default=DEFAULT_LOG_FILE, help="Path to text log file.")
    parser.add_argument("--queue-size", type=int, default=DEFAULT_QUEUE_MAX_SIZE, help="Maximum number of packets to buffer in memory.")
    parser.add_argument("--print-every", type=int, default=DEFAULT_PRINT_EVERY_N, help="Print a console line every N packets (0 to disable).")
    return parser.parse_args()

# ----- Main run function ----- #
def run_sniffer(network_interface, maximum_packets, output_path, log_path, max_queue_size, print_every_n):
    """
    Start writer thread, run scapy sniff, then shut down cleanly.
    Uses descriptive parameter names instead of sys.argv.
    """
    # update globals and logger based on CLI choices
    global logger, packet_queue, DEFAULT_PRINT_EVERY_N
    DEFAULT_PRINT_EVERY_N = print_every_n

    # reconfigure logger to use chosen log file
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    logger = logging.getLogger("packet_sniffer")
    logger.setLevel(logging.INFO)
    file_handler_local = logging.FileHandler(log_path, mode="a")
    file_handler_local.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logger.addHandler(file_handler_local)

    # recreate queue with chosen size
    packet_queue = queue.Queue(maxsize=max_queue_size)

    # start writer thread
    writer_thread = threading.Thread(target=writer_loop, args=(output_path,), daemon=True)
    writer_thread.start()

    # user-friendly start message
    start_message = "Starting packet capture on interface: " + str(network_interface) + " (max packets: " + str(maximum_packets) + ")"
    print(start_message)
    logger.info(start_message)

    # sniff packets; store=False to avoid keeping packets in memory
    try:
        if maximum_packets and maximum_packets > 0:
            sniff(iface=network_interface, prn=fast_packet_callback, store=False, count=maximum_packets)
        else:
            sniff(iface=network_interface, prn=fast_packet_callback, store=False)
    except KeyboardInterrupt:
        # user pressed Ctrl+C; proceed to shutdown
        print("User requested stop; finishing up.")
    finally:
        # tell writer to stop and send sentinel so it wakes quickly
        writer_stop_signal.set()
        try:
            packet_queue.put_nowait(None)
        except queue.Full:
            # if queue is full, writer will exit when it drains
            pass

        # wait for all queued items to be processed
        packet_queue.join()
        # wait briefly for writer thread to finish
        writer_thread.join(timeout=2.0)

        finish_message = "Capture finished. Output file: " + str(output_path)
        print(finish_message)
        logger.info(finish_message)

# ----- Script entrypoint ----- #
if __name__ == "__main__":
    arguments = parse_command_line_arguments()

    # pass descriptive variables into the run function
    run_sniffer(
        network_interface=arguments.interface,
        maximum_packets=arguments.max_packets,
        output_path=arguments.output_file,
        log_path=arguments.log_file,
        max_queue_size=arguments.queue_size,
        print_every_n=arguments.print_every
    )
