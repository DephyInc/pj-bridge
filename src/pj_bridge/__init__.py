"""pj-bridge: bridge a delimiter-framed binary stream into PlotJuggler.

Public library API. The CLI entry points live in the individual modules
(``bridge``, ``stream_parser``, ``socket_client``, ``derive_struct``,
``json_to_csv``); the names below are the stable surface for importing
pj-bridge as a library.
"""

from .derive_struct import derive_struct
from .socket_client import ws_sender
from .stream_parser import DelimitedRecordParser, parse_hex_u32
from .streamer import (
    DEFAULT_DELIMITER,
    DEFAULT_WS_URL,
    PlotJugglerStreamer,
    source_reader_to_queue,
)

__all__ = [
    "derive_struct",
    "DelimitedRecordParser",
    "parse_hex_u32",
    "ws_sender",
    "PlotJugglerStreamer",
    "source_reader_to_queue",
    "DEFAULT_WS_URL",
    "DEFAULT_DELIMITER",
]
