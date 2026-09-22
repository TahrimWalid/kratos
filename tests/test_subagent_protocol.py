"""Wire-protocol tests for the sub-agent<->core channel (capability 1)."""
from __future__ import annotations

import asyncio

import pytest

from kratos.subagent import protocol as proto


def test_encode_decode_round_trip():
    async def run():
        message = proto.build_telemetry(3, "2026-09-22T00:00:00+00:00", {"host": {"hostname": "web-01"}})
        frame = proto.encode_frame(message)
        reader = asyncio.StreamReader()
        reader.feed_data(frame)
        reader.feed_eof()
        decoded = await proto.read_frame(reader)
        assert decoded == message

    asyncio.run(run())


def test_clean_eof_before_any_bytes_returns_none():
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_eof()
        assert await proto.read_frame(reader) is None

    asyncio.run(run())


def test_eof_mid_header_raises_protocol_error():
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x00\x00")  # 2 of 4 length-prefix bytes
        reader.feed_eof()
        with pytest.raises(proto.ProtocolError):
            await proto.read_frame(reader)

    asyncio.run(run())


def test_eof_mid_body_raises_protocol_error():
    async def run():
        reader = asyncio.StreamReader()
        # Declare a 100-byte body but only supply 5 before EOF.
        reader.feed_data(proto._LENGTH.pack(100) + b"12345")
        reader.feed_eof()
        with pytest.raises(proto.ProtocolError):
            await proto.read_frame(reader)

    asyncio.run(run())


def test_oversized_declared_length_raises_frame_too_large():
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(proto._LENGTH.pack(proto.MAX_FRAME_BYTES + 1))
        with pytest.raises(proto.FrameTooLargeError):
            await proto.read_frame(reader)

    asyncio.run(run())


def test_encode_frame_rejects_oversized_message():
    huge = {"type": "telemetry", "payload": {"blob": "x" * (proto.MAX_FRAME_BYTES + 10)}}
    with pytest.raises(proto.FrameTooLargeError):
        proto.encode_frame(huge)


def test_malformed_json_body_raises_protocol_error():
    async def run():
        reader = asyncio.StreamReader()
        body = b"{not json"
        reader.feed_data(proto._LENGTH.pack(len(body)) + body)
        with pytest.raises(proto.ProtocolError):
            await proto.read_frame(reader)

    asyncio.run(run())


def test_non_object_json_body_raises_protocol_error():
    async def run():
        reader = asyncio.StreamReader()
        body = b"[1,2,3]"
        reader.feed_data(proto._LENGTH.pack(len(body)) + body)
        with pytest.raises(proto.ProtocolError):
            await proto.read_frame(reader)

    asyncio.run(run())


def test_object_without_type_field_raises_protocol_error():
    async def run():
        reader = asyncio.StreamReader()
        body = b'{"foo": "bar"}'
        reader.feed_data(proto._LENGTH.pack(len(body)) + body)
        with pytest.raises(proto.ProtocolError):
            await proto.read_frame(reader)

    asyncio.run(run())


def test_zero_length_frame_raises_protocol_error():
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(proto._LENGTH.pack(0))
        with pytest.raises(proto.ProtocolError):
            await proto.read_frame(reader)

    asyncio.run(run())


def test_message_builders_shape():
    hello = proto.build_hello("agent-1", {"token": "abc"}, "web-01", "0.1.0")
    assert hello["type"] == proto.MSG_HELLO
    assert hello["version"] == proto.PROTOCOL_VERSION

    ack = proto.build_hello_ack("tgt_1", "tok")
    assert ack == {"type": proto.MSG_HELLO_ACK, "target_id": "tgt_1", "token": "tok"}

    reject = proto.build_hello_reject("bad token")
    assert reject == {"type": proto.MSG_HELLO_REJECT, "reason": "bad token"}

    tel = proto.build_telemetry(1, "ts", {"a": 1})
    assert tel == {"type": proto.MSG_TELEMETRY, "seq": 1, "collected_at": "ts", "payload": {"a": 1}}

    ack2 = proto.build_telemetry_ack(1)
    assert ack2 == {"type": proto.MSG_TELEMETRY_ACK, "seq": 1}

    ping = proto.build_ping(123.0)
    assert ping == {"type": proto.MSG_PING, "ts": 123.0}

    pong = proto.build_pong(123.0)
    assert pong == {"type": proto.MSG_PONG, "ts": 123.0}
