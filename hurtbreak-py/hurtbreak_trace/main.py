from enum import IntEnum
import struct
from typing import BinaryIO, Self


class TraceError(Exception):
    """Base exception for trace errors."""


class Endian(IntEnum):
    LITTLE = 0x00
    BIG = 0x01

    @property
    def struct_prefix(self) -> str:
        return "<" if self == Endian.LITTLE else ">"


def crc8(data: bytes | bytearray) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) if crc & 0x80 else (crc << 1)
            crc &= 0xFF
    return crc


def encode_varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v != 0:
            b |= 0x80
        out.append(b)
        if v == 0:
            break
    return bytes(out)


def write_record(w: BinaryIO, rec_type: int, payload: bytes | bytearray) -> None:
    record = bytearray([rec_type])
    record.extend(encode_varint(len(payload) + 1))
    record.extend(payload)
    record.append(crc8(record))
    w.write(bytes(record))


class TraceStepBuilder:
    def __init__(self, ctx: "TraceContext", seed: int) -> None:
        self._ctx = ctx
        self._buf = bytearray(struct.pack(f"{ctx.endian.struct_prefix}Q", seed))
        self._buf.append(0)  # placeholder for field_count
        self._field_count = 0
        self._finished = False

    def add(self, field_id: int, data: bytes) -> Self:
        if self._finished:
            raise TraceError("cannot add to finished step")
        self._buf.append(field_id)
        self._buf.extend(data)
        self._field_count += 1
        return self

    def finish(self) -> None:
        if self._finished:
            raise TraceError("finish() already called")
        self._finished = True
        self._buf[8] = self._field_count
        write_record(self._ctx.writer, 0x02, self._buf)


class TraceContext:
    def __init__(self, writer: BinaryIO, endian: Endian) -> None:
        self._writer = writer
        self._endian = endian

    @property
    def writer(self) -> BinaryIO:
        return self._writer

    @property
    def endian(self) -> Endian:
        return self._endian

    def write_session_start(self, seed: int, tripwire_id: int) -> None:
        payload = struct.pack(f"{self._endian.struct_prefix}Q", seed)
        payload += encode_varint(tripwire_id)
        write_record(self._writer, 0x01, payload)

    def write_goal_reached(self, goal_id: int) -> None:
        write_record(self._writer, 0x03, encode_varint(goal_id))

    def write_failed_step(self, seed: int) -> None:
        payload = struct.pack(f"{self._endian.struct_prefix}Q", seed)
        write_record(self._writer, 0x04, payload)

    def begin_step(self, seed: int) -> TraceStepBuilder:
        return TraceStepBuilder(self, seed)


def hurt_write_header(
    w: BinaryIO,
    version: int,
    mode: int,
    endian: Endian,
    start_time: int,
) -> TraceContext:
    w.write(b"HURT")
    w.write(bytes([version, mode, endian]))
    w.write(struct.pack(f"{endian.struct_prefix}q", start_time))
    return TraceContext(w, endian)


if __name__ == "__main__":
    from pathlib import Path

    filepath = Path("py_test.hurt")
    with filepath.open("wb") as f:
        ctx = hurt_write_header(f, 0x01, 0x01, Endian.LITTLE, 1766371438000)
        ctx.write_session_start(0xDEADBEEF, 42)
        step = ctx.begin_step(0xCAFEBABE)
        step.add(0, bytes([1, 2, 3, 4]))
        step.add(1, bytes([0xFF]))
        step.finish()
        ctx.write_goal_reached(42)
    print(f"Wrote {filepath.stat().st_size} bytes to {filepath}")
