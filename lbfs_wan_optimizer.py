import wan_optimizer
import tcp_packet
import utils
import math

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to.
    GLOBAL_MATCH_BITSTRING = '0111011001010'

    # Window & Bitstring Size
    WINDOW_SIZE = 48
    BITSTRING_SIZE = len(GLOBAL_MATCH_BITSTRING)

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        
        # Dictionary to cache in potential duplicate *blocks*.
        # Entries have the form: (hash : raw data).
        self.cache = {}

        # Dictionary of buffers for each (packet.src, packet.dest) pairing.
        # Buffers are used to accumulate BLOCK_SIZE worth of payload or until an `is_fin` flag is detected.
        # Entries have the form: ((packet.src, packet.dest) : string).
        self.buffers = {}

        # Dictionary of window non inclusive end pointer for each (packet.src, packet.dest) buffer pairing.
        # Entries have the form: ((packet.src, packet.dest) : end).
        # Should be initialized to have value WINDOW_SIZE.
        self.pointers = {}


    def get_ptr(self, packet):
        """ Returns the non inclusive end pointer corr. to (packet.src, packet.dest).
        """
        return self.pointers[(packet.src, packet.dest)]

    def set_ptr(self, packet, value):
        """ Sets the non inclusive end pointer corr. to (packet.src, packet.dest). 
        """
        self.pointers[(packet.src, packet.dest)] = value

    def reset_ptr(self, packet):
        """ Resets the non inclusive end pointer corr. to (packet.src, packet.dest) to WINDOW_SIZE.
        """
        self.pointers[(packet.src, packet.dest)] = self.WINDOW_SIZE

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
        -> If we receive a hash (we must be an OPT(B)), we assume the block is in our cache so we get the corresponding block from the cache 
           and then send it via MULTIPLE packets using `send_block()`.
        -> If we receive raw data, then we want to keep sliding until we find a matching bitstring so that we have a defined block. Once we slide 
           until the end of the buffer and still no matching bitstring is found, two things can happen:
           1. The packet is a `fin` packet, so we must flush everything. Therefore, we treat the whole remaining block as a defined block.
           2. The packet is not a `fin` packet, so we just save the current state of the buffer and wait for the next packet to be received.

           Once we have the a defined block, we hash the block and two things can happen:
           1. The corr. hash is not in the cache that means its the first time seeing it. (OPT(A) and OPT(B))
              So we cache the hash along with the raw data and send the block of raw data to the appropriate next hop via MULTIPLE packets using `send_block()`.
           2. The corr. hash is in the cache that means we have seen this block before. (Only OPT(A) will reach this case)
              Therefore we send the hash in ONE packet to the next hop WAN using `send_single()`.
              (!!) An OPT(B) should NEVER EVER reach this case since if it did indeed cache this block before, a hash should be sent to it instead of raw data.

        """
        # Case when the packet received has raw data.
        if packet.is_raw_data:

            # Initialize a buffer for this (packet.src, packet.dest) pairing if none exist yet.
            if (packet.src, packet.dest) not in self.buffers:
                self.set_buf(packet, "")
                self.reset_ptr(packet)

            # `cur_buf` holds the current buffer including the incoming packet.
            cur_buf = self.get_buf(packet) + packet.payload
            cur_buf_len = len(cur_buf) 

            # In this case, we do not expect more packets to come. So we need to flush everything out of the buffer.
            if packet.is_fin:

                # The buffer is less than `WINDOW_SIZE` which means we cannot do bitstring matching and since we need to flush, we just cache it and send it along.
                if cur_buf_len < self.WINDOW_SIZE:
                    hashed_value = utils.get_hash(cur_buf)

                    # Cache if uncached and send along.
                    if hashed_value not in self.cache:
                        self.cache[hashed_value] = cur_buf 
                        self.send_single(packet, cur_buf, True)
                    # Since we have raw data input and it is cached, we must be OPT(A), so we send the hash instead.
                    else:
                        pkt = tcp_packet.Packet(packet.src, packet.dest, False, True, hashed_value)
                        self.send(pkt, self.wan_port)

                    # Reset buffer and end pointer
                    self.reset_buf(packet)
                    self.reset_ptr(packet)

                # Case where we have equal or more than 48 bytes in the buffer, so we keep sliding and flush everything.
                else:
                    # Keep looping until we flush everything
                    while (True):
                        end = self.get_ptr(packet)
                        start = end - self.WINDOW_SIZE
                        window = cur_buf[start:end]

                        # ----------------------------------------------------------------------------------------------------------------------
                        # The `window` length is smaller than `WINDOW_SIZE` when we slide past the buffer. This means we should cache the whole buffer
                        # and send tho whole buffer via MULTIPLE packets.
                        if len(window) < self.WINDOW_SIZE:
                            hashed_value = utils.get_hash(cur_buf)

                            # No matter if this is OPT(A) or OPT(B), if uncached, we cache it and send the whole buffer via MULTIPLE packets.
                            if hashed_value not in self.cache:
                                self.cache[hashed_value] = cur_buf
                                # The last packet shld have `is_fin` set to True.
                                self.send_block(packet, cur_buf, True)

                            # Since we have raw data input and it is cached, we must be OPT(A), so we send the hash to WAN via a SINGLE packet.
                            else:
                                # Construct packet w/ payload = hashed_value and send it out to the next WAN.
                                pkt = tcp_packet.Packet(packet.src, packet.dest, False, True, hashed_value)
                                self.send(pkt, self.wan_port)

                            # Reset buffer and end pointer
                            self.reset_buf(packet)
                            self.reset_ptr(packet)
                            break
                        # ----------------------------------------------------------------------------------------------------------------------

                        hashed_window = utils.get_hash(window)
                        bitstring = utils.get_last_n_bits(hashed_window, self.BITSTRING_SIZE)
    
                        # We have a matching bitstring so we now have a defined block
                        if (bitstring == self.GLOBAL_MATCH_BITSTRING):
                            # The defined block should be from the very front of the buffer up till the end of the window.
                            defined_block = cur_buf[:end]
                            hashed_value = utils.get_hash(defined_block)

                            # No matter if this is OPT(A) or OPT(B), if uncached, we cache the hash and send the whole block via MULTIPLE packets.
                            if hashed_value not in self.cache:
                                self.cache[hashed_value] = defined_block
                                # This is not the last packet so we pass in `is_fin` as False.
                                self.send_block(packet, defined_block, False)

                            # Since we have raw data input and it is cached, we must be OPT(A), so we send the hash to WAN via a SINGLE packet.
                            else:
                                # Construct packet w/ payload = hashed_value and send it out to the next WAN.
                                pkt = tcp_packet.Packet(packet.src, packet.dest, False, False, hashed_value)
                                self.send(pkt, self.wan_port)

                            # Now we need to remove the processed portion of the buffer and set the appropriate length.
                            cur_buf = cur_buf[end:]
                            cur_buf_len = len(cur_buf)

                            # Since the buffer is partially processed, we need to reset the end pointer.
                            self.reset_ptr(packet)

                        # We did not get a matching bitstring, so we slide by a byte, i.e. we increment the end pointer, and then reloop.
                        else:
                            self.set_ptr(packet, end + 1)


            # In this case, `is_fin` is False which means we expect more packets, so we just process however much of the buffer we can.
            else:
                # The buffer is less than `WINDOW_SIZE` which means we cannot do bitstring matching and since we DON'T need to flush, 
                # we just update the buffer in our cache and wait for the next packet to arrive.
                if cur_buf_len < self.WINDOW_SIZE:
                    self.set_buf(packet, cur_buf)

                # Case where we have equal or more than 48 bytes in the buffer, so we keep sliding and trying to find and process defined blocks.
                # If there is anything remaining in the buffer, just save that buffer and record the pointer to where we left off.
                else:
                    # Keep looping and processing.
                    while (True):
                        end = self.get_ptr(packet)
                        start = end - self.WINDOW_SIZE
                        window = cur_buf[start:end]

                        # ----------------------------------------------------------------------------------------------------------------------
                        # The `window` length is smaller than `WINDOW_SIZE` when we slide past the buffer. This means we should just save the whole buffer.
                        # Since the end pointer was not modified, we don't need to do anything to it.
                        if len(window) < self.WINDOW_SIZE:
                            self.set_buf(packet, cur_buf)
                            break
                        # ----------------------------------------------------------------------------------------------------------------------

                        hashed_window = utils.get_hash(window)
                        bitstring = utils.get_last_n_bits(hashed_window, self.BITSTRING_SIZE)
    
                        # We have a matching bitstring so we now have a defined block
                        if (bitstring == self.GLOBAL_MATCH_BITSTRING):
                            # The defined block should be from the very front of the buffer till the end of the window.
                            defined_block = cur_buf[:end]
                            hashed_value = utils.get_hash(defined_block)

                            # No matter if this is OPT(A) or OPT(B), if uncached, we cache the hash and send the whole block via MULTIPLE packets.
                            if hashed_value not in self.cache:
                                self.cache[hashed_value] = defined_block
                                # This is not the last packet so we pass in `is_fin` as False.
                                self.send_block(packet, defined_block, False)

                            # Since we have raw data input and it is cached, we must be OPT(A), so we send the hash to WAN via a SINGLE packet.
                            else:
                                # Construct packet w/ payload = hashed_value and send to the next WAN.
                                pkt = tcp_packet.Packet(packet.src, packet.dest, False, False, hashed_value)
                                self.send(pkt, self.wan_port)

                            # Now we need to remove the processed portion of the buffer
                            cur_buf = cur_buf[end:]
                            cur_buf_len = len(cur_buf)

                            # Since the buffer is partially processed, we need to reset the end pointer.
                            self.reset_ptr(packet)

                        # We did not get a matching bitstring, so we slide by a byte, i.e. we increment the end pointer, and then reloop.
                        else:
                            self.set_ptr(packet, end + 1)

        # Case when the packet received is a hash (this MUST be an OPT(B)).
        # When a hash was received, it means that the block should be in the cache.
        else:
            # Obtain the cached block from cache and send it via `send_block()`.
            defined_block = self.cache[packet.payload]
            # The last packet sent should inherit `packet.is_fin`.
            self.send_block(packet, defined_block, packet.is_fin)


