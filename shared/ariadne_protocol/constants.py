"""Wire-protocol constants. Keep these stable; bump PROTOCOL_VERSION on breaks."""

PROTOCOL_VERSION = 1

DEFAULT_HOST = "127.0.0.1"
DEFAULT_BN_PORT = 9337
DEFAULT_GDB_PORT = 9338

# XML-RPC <int> is 32-bit. Addresses travel as hex strings (see types.dumps_addr).
ADDR_PREFIX = "0x"

# Bound every GDB memory transfer so a bad Julia call cannot dump the process.
MAX_MEMORY_TRANSFER = 1 << 20  # 1 MiB

# Latest-PC coalescing: drop queued highlight jobs older than this many ms.
PC_COALESCE_MS = 15

# Stack-variable cache: function-start -> layout. Sized for a typical session.
STACK_CACHE_MAX_FUNCTIONS = 512
