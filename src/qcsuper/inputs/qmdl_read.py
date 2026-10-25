#!/usr/bin/env python3
# -*- encoding: Utf-8 -*-
from datetime import datetime
from struct import unpack
from ..protocol.messages import *

from ._base_input import BaseInput
from ._hdlc_mixin import HdlcMixin

"""
    
"""

TIMESTAMP_OFFSET = datetime(1980, 1, 6).timestamp()
TIMESTAMP_MIN = datetime(2010, 1, 1).timestamp()
TIMESTAMP_MAX = datetime(2050, 1, 1).timestamp()

class QmdlReader(HdlcMixin, BaseInput):
    def __init__(self, qmdl_file):

        self.qmdl_file = qmdl_file

        # We keep track of the timestamp of the latest read packet, in the case
        # where the next packet we'll read happens to use an uncommon format

        self.timestamp = 0

        super().__init__()

    def read_loop(self):
        buffer = b''
        while chunk := self.qmdl_file.read(1024 * 1024):
            buffer += chunk
            while self.TRAILER_CHAR in buffer:

                raw_payload, buffer = buffer.split(self.TRAILER_CHAR, 1)
                if not raw_payload:
                    continue
                try:
                    packet = self.hdlc_decapsulate(payload=raw_payload + self.TRAILER_CHAR)
                except self.InvalidFrameError:
                    continue

                if packet[0] == DIAG_MULTI_RADIO_CMD_F:
                    packet = packet[8:]
                    
                if packet[0] == DIAG_LOG_F:
                    log_header = packet[4:16]
                    log_data = packet[16:]
                    _, log_type, log_time = unpack('<HHQ', log_header)
                    
                    log_time = (
                        (log_time >> 20) / 50
                        + TIMESTAMP_OFFSET
                        + ((log_time & 0xFFFFF) / 0x100000) / 50  # mantissa of a 20 ms unit
                    )
        
                    if TIMESTAMP_MIN <= log_time <= TIMESTAMP_MAX:
                        self.timestamp = log_time

                    self.dispatch_diag_log(log_type, log_data, log_header, self.timestamp)