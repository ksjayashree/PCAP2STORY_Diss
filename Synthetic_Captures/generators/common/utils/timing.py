"""Realistic timing models for BGP traffic generation.

Provides jittered intervals, burst timing, and pause models
to make synthetic captures look realistic.
"""

import random
import math
from typing import Generator


def jittered_interval(base: float, jitter_pct: float = 0.1) -> float:
    """Generate a jittered interval around a base value.
    
    Args:
        base: Base interval in seconds (e.g., 10.0 for keepalive)
        jitter_pct: Maximum jitter as fraction of base (default 10%)
    
    Returns:
        Jittered interval value
    """
    jitter = base * jitter_pct
    return base + random.uniform(-jitter, jitter)


def keepalive_timestamps(start_time: float, duration: float, 
                         keepalive_interval: float = 10.0,
                         jitter_pct: float = 0.15) -> Generator[float, None, None]:
    """Generate keepalive timestamps over a duration.
    
    Models realistic keepalive timing with natural jitter.
    Real BGP implementations don't fire keepalives at exact intervals.
    
    Args:
        start_time: Capture start time (seconds)
        duration: Total duration to generate (seconds)
        keepalive_interval: Base keepalive interval (seconds)
        jitter_pct: Jitter percentage (default 15% based on real captures)
    
    Yields:
        Timestamps for each keepalive
    """
    t = start_time + jittered_interval(keepalive_interval, jitter_pct)
    end_time = start_time + duration
    while t < end_time:
        yield t
        t += jittered_interval(keepalive_interval, jitter_pct)


def ack_delay(base_rtt: float = 0.001) -> float:
    """Generate realistic ACK delay (sub-millisecond for LAN).
    
    Args:
        base_rtt: Base round-trip time in seconds
    
    Returns:
        ACK delay in seconds
    """
    return base_rtt * random.uniform(0.3, 0.8)


def route_burst_timestamps(start_time: float, num_updates: int,
                           inter_update_ms: float = 5.0) -> list[float]:
    """Generate timestamps for a burst of route updates.
    
    Models how BGP implementations send multiple UPDATEs in quick succession
    (e.g., after session establishment or soft-reset).
    
    Args:
        start_time: Start time of burst
        num_updates: Number of UPDATE messages in burst
        inter_update_ms: Average time between updates in milliseconds
    
    Returns:
        List of timestamps
    """
    timestamps = []
    t = start_time
    for _ in range(num_updates):
        timestamps.append(t)
        # Small random gap between updates (1-10ms typically)
        t += random.uniform(inter_update_ms * 0.2, inter_update_ms * 1.5) / 1000.0
    return timestamps


def hold_timer_expiry_delay(hold_timer: float) -> float:
    """Time for hold timer to actually expire (slightly > configured value).
    
    In practice, implementations detect hold timer expiry slightly after
    the exact configured time due to processing delays.
    
    Args:
        hold_timer: Configured hold timer in seconds
    
    Returns:
        Actual expiry time in seconds
    """
    return hold_timer + random.uniform(0.1, 0.5)


def reconnection_delay(base_retry: float = 30.0, attempt: int = 1) -> float:
    """Generate reconnection delay with exponential backoff.
    
    Models BGP connect-retry behavior.
    
    Args:
        base_retry: Base retry timer in seconds
        attempt: Attempt number (1-based)
    
    Returns:
        Delay before next attempt in seconds
    """
    # Capped exponential backoff with jitter
    delay = min(base_retry * (2 ** (attempt - 1)), 120.0)
    return delay + random.uniform(0, delay * 0.2)


def session_establishment_duration() -> float:
    """Time for full BGP session establishment (handshake + OPEN + KEEPALIVE).
    
    Returns:
        Duration in seconds (typically 0.01 - 0.5s on LAN)
    """
    return random.uniform(0.01, 0.1)


def route_advertisement_delay(num_routes: int) -> float:
    """Time to advertise N routes after session establishment.
    
    Args:
        num_routes: Number of routes to advertise
    
    Returns:
        Duration in seconds
    """
    # Roughly 1-5ms per route for moderate-speed implementations
    per_route_ms = random.uniform(1.0, 5.0)
    return (num_routes * per_route_ms) / 1000.0
