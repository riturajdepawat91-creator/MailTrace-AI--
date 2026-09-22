import socket
import time

from ..models import ProviderResult


def reverse_dns(ip: str) -> ProviderResult:

    started = time.perf_counter()

    try:
        hostname, aliases, addresses = socket.gethostbyaddr(ip)

        latency = round(
            (time.perf_counter() - started) * 1000,
            2
        )

        return ProviderResult(
            provider="reverse_dns",
            success=True,
            data={
                "hostname": hostname,
                "aliases": aliases,
                "addresses": addresses,
            },
            latency_ms=latency,
        )

    except (
        socket.herror,
        socket.gaierror,
        OSError
    ) as error:

        latency = round(
            (time.perf_counter() - started) * 1000,
            2
        )

        return ProviderResult(
            provider="reverse_dns",
            success=False,
            error=str(error),
            latency_ms=latency,
        )
