import wan_optimizer
import tcp_packet
import utils
import math

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into fixed-size blocks.

    This WAN optimizer should implement part 1 of project 4.
    """

    # Size of blocks to store, and send only the hash when the block has been sent previously
    BLOCK_SIZE = 8000

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        
        # Dictionary to cache in potential duplicate *blocks*.
        # Entries have the form: (hash : raw data).
        self.cache = {}

        # Dictionary of buffers for each (packet.src, packet.dest) pairing.
        # Buffers are used to accumulate BLOCK_SIZE worth of payload or until an `is_fin` flag is detected.
        # Entries have the form: ((packet.src, packet.dest) : string).
        self.buffers = {}

    def get_buf(self, packet):
        """ Returns the buffer string value corr. to (packet.src, packet.dest).
        """
        return self.buffers[(packet.src, packet.dest)]

    def set_buf(self, packet, value):
        """ Sets the buffer corr. to (packet.src, packet.dest) to value.
        """
        self.buffers[(packet.src, packet.dest)] = value

    def reset_buf(self, packet):
        """ Resets the buffer corr. to (packet.src, packet.dest) to "" (empty string).
        """
        self.buffers[(packet.src, packet.dest)] = ""

    def is_receiver(self, packet):
        """ Returns True if this WAN Optimizer is type OPT(B), i.e. on the receiving side.
            Returns False if this WAN Optimizer is type OPT(A), i.e. on the sending side.
        """
        if packet.dest in self.address_to_port:
            return True
        else:
            return False

    def send_single(self, packet, payload, is_fin):
        """ A helper function to send just a single packet to its "appropriate" destination.
            The difference between this function and the base `wan_optimizer.send()` function is that:
            The base function sends the input `packet` to a `dest`.
            This function CREATES a packet using the input params and determines its destination based on `packet.dest` and then sends it.

            PARAMS:
            packet: We will extract packet.src and packet.dest from this param.
            block: Raw payload that should fit in the SINGLE packet that will be created and sent.
            is_fin: Whether this new packet should be a `fin` packet.
        """

        # Construct a packet from input params. Assumes that `is_raw_data` is True.
        pkt = tcp_packet.Packet(packet.src, packet.dest, True, is_fin, payload)

        # This is a OPT(B) so we send to a client.
        if self.is_receiver(packet):
            self.send(pkt, self.address_to_port[packet.dest])

        # This is a OPT(A) so we send to the WAN. 
        else:
            self.send(pkt, self.wan_port)


    def send_block(self, packet, raw_data_block, is_fin):
        """ A helper function to split the `BLOCK_SIZE`d `raw_data_block` into packet sized chunks and send them with `send_single()`.

            PARAMS:
            packet: Will be used as argument to `send_single()` to extract `packet.src` and `packet.dest`.
            raw_data_block: The `BLOCK_SIZE`d big payload that should be split and sent via MULTIPLE packets.
            is_fin: The last packet sent shld carry whatever `is_fin` is set to. All other packets should have `is_fin` False.
        """

        # Determine how many packets we need to fully send out `raw_data_block`.
        size = len(raw_data_block)
        # The max is to address that there might be a `fin` packet that has no payload.
        num_packets = max(int(math.ceil(size*1.0 / utils.MAX_PACKET_SIZE)), 1)

        # Iteratively create packets and send them using `send_single()`
        for i in range(num_packets):
            start = (i * utils.MAX_PACKET_SIZE) + 0
            end = (i * utils.MAX_PACKET_SIZE) + utils.MAX_PACKET_SIZE
            payload = raw_data_block[start:end]

            # The last sent packet will inherit the `is_fin` param.
            if (i == num_packets - 1): 
                self.send_single(packet, payload, is_fin)
            # Otherwise, `is_fin` will be False.
            else:
                self.send_single(packet, payload, False)


    def receive(self, packet):
        """ Handles receiving a packet.

        We define two types of OPT:
        OPT(A): The OPT on the sending side. This type of OPT can ONLY receive raw data but can send both raw data or hashes.
        OPT(B): The OPT on the receiving side. This type of OPT can receive both raw data and hashes but can ONLY send raw data.
        ** This is evidence that a OPT is a middle box, i.e. clients receive and send ONLY raw data.

        A WAN optimizer can receive packets in 2 forms:
        1. The payload is raw data  ->  The packet is from a client to an OPT(A)/OPT(B) OR 
                                        The packet is from the WAN to an OPT(B) and this OPT(B) hasn't cached it yet.
        2. The payload is a hash    ->  The packet is from the WAN to an OPT(B) and this OPT(B) has already cached it.

        Processing:
        -> If we receive a hash (we must be an OPT(B)), we get the corresponding block from the cache and then send it via MULTIPLE packets using `send_block()`.
        -> If we receive raw data, then we need to accumulate `BLOCK_SIZE` worth of data before we can process anything.
           Once we have the `BLOCK` accumulated, we hash the block and two things can happen:
           1. The corr. hash is not in the cache that means its the first time seeing it. (OPT(A) and OPT(B))
              So we cache the hash along with the raw data and send the block of raw data to the appropriate next hop via MULTIPLE packets using `send_block()`.
           2. The corr. hash is in the cache that means we have seen this `BLOCK` before. (Only OPT(A) will reach this case)
              Therefore we send the hash in ONE packet to the next hop WAN using `send_single()`.
              (!!) An OPT(B) should NEVER EVER reach this case since if it did indeed cache this `BLOCK` before, a hash should be sent to it instead of raw data.

        """

        # Case when the packet received has raw data.
        if packet.is_raw_data:

            # Initialize a buffer for this (packet.src, packet.dest) pairing if none exist yet.
            if (packet.src, packet.dest) not in self.buffers:
                self.set_buf(packet, "")

            cur_buf_len = len(self.get_buf(packet))
            cur_pkt_len = len(packet.payload)

            # Decide course of action based on how much is the buffer filled.
            # Case where we have buffer be exactly full, i.e. no overflow.
            if (cur_buf_len + cur_pkt_len == self.BLOCK_SIZE):

                raw_data_block = self.get_buf(packet) + packet.payload
                hashed_value = utils.get_hash(raw_data_block)

                # No matter if this is OPT(A) or OPT(B), if uncached, we cache the hash and send the whole block via MULTIPLE packets.
                if hashed_value not in self.cache:
                    self.cache[hashed_value] = raw_data_block
                    # `packet.is_fin` should be passed in due to inheritance.
                    self.send_block(packet, raw_data_block, packet.is_fin)

                # Since we have raw data input and it is cached, we must be OPT(A), so we send the hash to WAN via a SINGLE packet.
                else:
                    # Construct packet w/ payload = hashed_value
                    # `packet.is_fin` should be passed in due to inheritance.
                    pkt = tcp_packet.Packet(packet.src, packet.dest, False, packet.is_fin, hashed_value)
                    self.send(pkt, self.wan_port)

                # We have finished processing the accumulated buffer, so we reset the buffer.
                self.reset_buf(packet)

            # Case where we have buffer overflow so we process one block and store the excess overflowed portion in the buffer.
            # There is an edge case where if this overflowing packet is a `fin` packet, then we would have to send it too.
            elif (cur_buf_len + cur_pkt_len > self.BLOCK_SIZE):

                # Split out the overflowed portion
                portion_main = packet.payload[0:(self.BLOCK_SIZE - cur_buf_len)]
                portion_overflow = packet.payload[(self.BLOCK_SIZE - cur_buf_len):]
                raw_data_block = self.get_buf(packet) + portion_main
                hashed_value = utils.get_hash(raw_data_block)

                # Deal with main portion (the full block) first
                # No matter if this is OPT(A) or OPT(B), if uncached, we cache the hash and send the whole block via MULTIPLE packets.
                if hashed_value not in self.cache:
                    self.cache[hashed_value] = raw_data_block
                    # Since this is the overflow case, the `is_fin` flag we pass in must be False.
                    self.send_block(packet, raw_data_block, False)

                # Since we have raw data input and it is cached, we must be OPT(A), so we send the hash to WAN via a SINGLE packet.
                else:
                    # Construct packet w/ payload = hashed_value
                    # Since this is the overflow case, the `is_fin` flag we pass in must be False.
                    pkt = tcp_packet.Packet(packet.src, packet.dest, False, False, hashed_value)
                    self.send(pkt, self.wan_port)

                # We have finished processing the accumulated buffer, so we reset the buffer.
                self.reset_buf(packet)

                # Now deal with overflowed portion. (!!) Overflowed portion MUST fit in a single packet.
                # Immediately deal with overflowed portions from `fin` packets.
                if packet.is_fin:
                    overflow_hashed_value = utils.get_hash(portion_overflow)

                    # No matter if this is OPT(A) or OPT(B), if uncached, we cache the hash and send the whole block via a SINGLE packet to appropriate destination.
                    if overflow_hashed_value not in self.cache:
                        self.cache[overflow_hashed_value] = portion_overflow
                        # The `is_fin` flag we pass in must be True.
                        self.send_single(packet, portion_overflow, True)

                    # Since we have raw data input and it is cached, we must be OPT(A), so we send the hash to WAN via a SINGLE packet.
                    else:
                        # Construct packet w/ payload = overflow_hashed_value
                        # The `is_fin` flag we pass in must be True.
                        pkt_to_send = tcp_packet.Packet(packet.src, packet.dest, False, True, overflow_hashed_value)
                        self.send(pkt_to_send, self.wan_port)

                # If overflowed packet is not `fin` packet, then just store the overflowed portion in the buffer
                else:
                    self.set_buf(packet, portion_overflow)
 
            # Case where we don't have a full buffer. So, we only need to process if the packet's `is_fin` is set to True.
            else:
                if packet.is_fin:
                    raw_data_block = self.get_buf(packet) + packet.payload
                    hashed_value = utils.get_hash(raw_data_block)

                    # No matter if this is OPT(A) or OPT(B), if uncached, we cache the hash and send the whole block via MULTIPLE packets.
                    if hashed_value not in self.cache:
                        self.cache[hashed_value] = raw_data_block
                        # The `is_fin` flag we pass in must be True.
                        self.send_block(packet, raw_data_block, True)

                    # Since we have raw data input and it is cached, we must be OPT(A), so we send the hash to WAN via a SINGLE packet.
                    else:
                        # Construct packet w/ payload = hashed_value.
                        # The `is_fin` flag we pass in must be True.
                        pkt_to_send = tcp_packet.Packet(packet.src, packet.dest, False, True, hashed_value)
                        self.send(pkt_to_send, self.wan_port)

                    # We have finished processing the "even though not full but has a `fin` packet" buffer, so we reset the buffer.
                    self.reset_buf(packet)

                # Just put stuff in the buffer
                else: 
                    self.set_buf(packet, self.get_buf(packet) + packet.payload)

        # Case when the packet received is a hash (this MUST be an OPT(B)).
        # When a hash was received, it means that the block should be in the cache.
        else:
            # Obtain the cached block from cache and send it via `send_block()`.
            raw_data_block = self.cache[packet.payload]
            self.send_block(packet, raw_data_block, packet.is_fin)

