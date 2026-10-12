"""Decoder for the Google Safe Browsing v5 `hashes.search` answer, which the live endpoint sends as binary Protocol Buffers (Content-Type: application/x-protobuf).

SCHEMA (Google's published definition, googleapis/google/security/safebrowsing/v5/safebrowsing.proto; the v5 overview says "all of the response bodies are protocol-buffer formatted payload"):

    message SearchHashesResponse { repeated FullHash full_hashes = 1; google.protobuf.Duration cache_duration = 2; }
    message FullHash             { bytes full_hash = 1;  repeated FullHashDetail full_hash_details = 2; }
    message FullHashDetail       { ThreatType threat_type = 1;  repeated ThreatAttribute attributes = 2; }
    google.protobuf.Duration     { int64 seconds = 1;  int32 nanos = 2; }
    enum ThreatType      { THREAT_TYPE_UNSPECIFIED = 0; MALWARE = 1; SOCIAL_ENGINEERING = 2; UNWANTED_SOFTWARE = 3; POTENTIALLY_HARMFUL_APPLICATION = 4; }
    enum ThreatAttribute { THREAT_ATTRIBUTE_UNSPECIFIED = 0; CANARY = 1; FRAME_ONLY = 2; }

This is a small, strict reader of the protobuf WIRE FORMAT (varints, length-delimited fields, fixed32/fixed64 skipping) driven by exactly that schema - it does not guess field positions:
every field is looked up by its schema number and must have the wire type the schema requires; unknown fields (a newer server) are skipped by their wire type, as the protocol allows; repeated
scalar enums are accepted both packed and unpacked; an empty body is the valid empty message (no hashes, no cache duration); anything truncated, over-long, mistyped or out of range raises
ProtobufError, which the adapter reports as a failed lookup - never as "no match". It is cross-checked in the tests against messages produced by the official `protobuf` library.
Standard library only; Python 3.8 compatible.
"""

MAX_BODY_BYTES = 1 << 20          # an answer for at most 1000 prefixes is far smaller; anything bigger is refused
MAX_ENTRIES = 10000
MAX_NESTING_BYTES = MAX_BODY_BYTES
FULL_HASH_BYTES = 32

THREAT_TYPES = {0: "THREAT_TYPE_UNSPECIFIED", 1: "MALWARE", 2: "SOCIAL_ENGINEERING", 3: "UNWANTED_SOFTWARE", 4: "POTENTIALLY_HARMFUL_APPLICATION"}
THREAT_ATTRIBUTES = {0: "THREAT_ATTRIBUTE_UNSPECIFIED", 1: "CANARY", 2: "FRAME_ONLY"}

VARINT, FIXED64, LENGTH_DELIMITED, START_GROUP, END_GROUP, FIXED32 = 0, 1, 2, 3, 4, 5


class ProtobufError(ValueError):
    """The body is not a valid message of the documented schema. The text names the rule; it never contains any of the body."""


def read_varint(data, position):
    """(value, next position) of a base-128 varint (at most 10 bytes, as a 64-bit value requires)."""
    result = 0
    shift = 0
    for count in range(10):
        if position >= len(data):
            raise ProtobufError("a varint is cut off at the end of the body")
        byte = data[position]
        position += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, position
        shift += 7
    raise ProtobufError("a varint is longer than 10 bytes")


def iter_fields(data):
    """(field number, wire type, value) for every field of one message, in order. value: int (varint / fixed), or bytes (length-delimited)."""
    position = 0
    size = len(data)
    while position < size:
        key, position = read_varint(data, position)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise ProtobufError("field number 0 is not valid")
        if wire == VARINT:
            value, position = read_varint(data, position)
        elif wire == LENGTH_DELIMITED:
            length, position = read_varint(data, position)
            if length > size - position:
                raise ProtobufError("a field claims %d bytes but only %d remain" % (length, size - position))
            value = bytes(data[position:position + length])
            position += length
        elif wire == FIXED64:
            if size - position < 8:
                raise ProtobufError("a fixed64 field is cut off")
            value = int.from_bytes(data[position:position + 8], "little")
            position += 8
        elif wire == FIXED32:
            if size - position < 4:
                raise ProtobufError("a fixed32 field is cut off")
            value = int.from_bytes(data[position:position + 4], "little")
            position += 4
        else:
            raise ProtobufError("wire type %d (groups) is not used by this schema" % wire)
        yield number, wire, value


def _signed(value, bits):
    """A varint read as a two's-complement signed integer of the given width (int32 / int64 fields)."""
    value &= (1 << 64) - 1
    if bits == 32:
        value &= 0xFFFFFFFF
        return value - (1 << 32) if value >= (1 << 31) else value
    return value - (1 << 64) if value >= (1 << 63) else value


def _enum_values(wire, value, what):
    """The values of one occurrence of a REPEATED enum field: a single varint (unpacked) or a length-delimited run of varints (packed). Both are valid."""
    if wire == VARINT:
        return [value]
    if wire == LENGTH_DELIMITED:
        values, position = [], 0
        while position < len(value):
            item, position = read_varint(value, position)
            values.append(item)
        return values
    raise ProtobufError("%s has the wrong wire type" % what)


def _duration(data):
    seconds, nanos = 0, 0
    for number, wire, value in iter_fields(data):
        if number == 1:
            if wire != VARINT:
                raise ProtobufError("Duration.seconds has the wrong wire type")
            seconds = _signed(value, 64)
        elif number == 2:
            if wire != VARINT:
                raise ProtobufError("Duration.nanos has the wrong wire type")
            nanos = _signed(value, 32)
    if seconds < 0 or not 0 <= nanos <= 999999999 or (seconds == 0 and nanos < 0):
        raise ProtobufError("the cache duration is out of range")
    return seconds + nanos / 1e9


def _detail(data):
    threat_type, attributes = 0, []
    for number, wire, value in iter_fields(data):
        if number == 1:
            if wire != VARINT:
                raise ProtobufError("threat_type has the wrong wire type")
            threat_type = value
        elif number == 2:
            attributes.extend(_enum_values(wire, value, "attributes"))
    return {"threat_type": threat_type, "attributes": attributes}


def _full_hash(data):
    digest, details = b"", []
    for number, wire, value in iter_fields(data):
        if number == 1:
            if wire != LENGTH_DELIMITED:
                raise ProtobufError("full_hash has the wrong wire type")
            digest = value
        elif number == 2:
            if wire != LENGTH_DELIMITED:
                raise ProtobufError("full_hash_details has the wrong wire type")
            details.append(_detail(value))
    if len(digest) != FULL_HASH_BYTES:
        raise ProtobufError("a full hash is %d bytes, %d are required" % (len(digest), FULL_HASH_BYTES))
    return {"full_hash": digest, "details": details}


def decode_search_hashes_response(body):
    """bytes -> {"full_hashes": [{"full_hash": bytes(32), "details": [{"threat_type": int, "attributes": [int]}]}], "cache_seconds": float or None}.
    cache_seconds is None when the message carries no cache duration. Raises ProtobufError for anything that is not a valid SearchHashesResponse."""
    if not isinstance(body, (bytes, bytearray)):
        raise ProtobufError("the body is not bytes")
    if len(body) > MAX_BODY_BYTES:
        raise ProtobufError("the body is larger than %d bytes" % MAX_BODY_BYTES)
    hashes, cache = [], None
    for number, wire, value in iter_fields(bytes(body)):
        if number == 1:
            if wire != LENGTH_DELIMITED:
                raise ProtobufError("full_hashes has the wrong wire type")
            hashes.append(_full_hash(value))
            if len(hashes) > MAX_ENTRIES:
                raise ProtobufError("more than %d full hashes" % MAX_ENTRIES)
        elif number == 2:
            if wire != LENGTH_DELIMITED:
                raise ProtobufError("cache_duration has the wrong wire type")
            cache = _duration(value)
    return {"full_hashes": hashes, "cache_seconds": cache}
