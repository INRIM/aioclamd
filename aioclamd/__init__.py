import asyncio
import re
import struct
from typing import Union, BinaryIO

try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:  # Python < 3.8
    from importlib_metadata import version, PackageNotFoundError  # type: ignore

try:
    __version__ = version("aioclamd")
except PackageNotFoundError:
    __version__ = ""

scan_response = re.compile(
    r"^(?P<path>.*): ((?P<virus>.+) )?(?P<status>(FOUND|OK|ERROR))$"
)


class ClamdError(Exception):
    """Base exception for aioclamd"""


class ResponseError(ClamdError):
    """Class for errors when parsing response."""


class BufferTooLongError(ResponseError):
    """
    Class for errors with clamd using INSTREAM with a buffer
    length > StreamMaxLength in /etc/clamav/clamd.conf
    """


class ClamdConnectionError(ClamdError):
    """Class for errors communication with clamd"""


def _parse_response(msg):
    """
    parses responses for SCAN, CONTSCAN, MULTISCAN and STREAM commands.
    """
    try:
        return scan_response.match(msg).group("path", "virus", "status")
    except AttributeError:
        raise ResponseError(msg.rsplit("ERROR", 1)[0])


class _AsyncClamdNetworkSocket:
    """Context manager helper to make Clamd calls."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3310,
    ):
        self.host = host
        self.port = port
        self.reader: Union[asyncio.StreamReader, None] = None
        self.writer: Union[asyncio.StreamWriter, None] = None

    async def __aenter__(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port
            )
        except Exception as e:
            raise ClamdConnectionError(
                f"Error connecting to {self.host}:{self.port}"
            ) from e
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass

    async def basic_command(self, command):
        await self.send_command(command)
        response = (await self.recv_response()).rsplit("ERROR", 1)
        if len(response) > 1:
            raise ResponseError(response[0])
        return response[0]

    async def send_command(self, cmd, *args):
        cmd_to_send = f"n{cmd}{' ' + ' '.join(args) if args else ''}\n".encode("utf-8")
        self.writer.write(cmd_to_send)
        await self.writer.drain()

    async def recv_response(self) -> str:
        try:
            line = await self.reader.read()
            return line.decode("utf-8").strip()
        except Exception as e:
            raise ClamdConnectionError("Error while reading from socket") from e


class ClamdAsyncClient:
    """Class for using clamd through a network socket."""

    def __init__(
        self, host: str = "127.0.0.1", port: int = 3310, timeout: float = None
    ):
        self.host = host
        self.port = port
        self.timeout = timeout

    async def instream(self, buffer: BinaryIO) -> dict:
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            await socket.send_command("INSTREAM")

            chunk_size = 1024
            chunk = buffer.read(chunk_size)
            while chunk:
                size = struct.pack(b"!L", len(chunk))
                socket.writer.write(size + chunk)
                await socket.writer.drain()
                chunk = buffer.read(chunk_size)

            socket.writer.write(struct.pack(b"!L", 0))

            result = await socket.recv_response()

            if result:
                if result == "INSTREAM size limit exceeded. ERROR":
                    raise BufferTooLongError(result)

                filename, reason, status = _parse_response(result)
                return {filename: (status, reason)}

    async def _file_system_scan(self, command, file):
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            await socket.send_command(command, file)
            dr = {}
            response = await socket.recv_response()
            for result in response.split("\n"):
                if result:
                    filename, reason, status = _parse_response(result)
                    dr[filename] = (status, reason)
            return dr

    async def ping(self):
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            return await socket.basic_command("PING")

    async def version(self):
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            return await socket.basic_command("VERSION")

    async def reload(self):
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            return await socket.basic_command("RELOAD")

    async def shutdown(self):
        async with _AsyncClamdNetworkSocket(self.host, self.port) as socket:
            return await socket.basic_command("SHUTDOWN")

    async def scan(self, file):
        return await self._file_system_scan("SCAN", file)

    async def contscan(self, file):
        return await self._file_system_scan("CONTSCAN", file)

    async def multiscan(self, file):
        return await self._file_system_scan("MULTISCAN", file)