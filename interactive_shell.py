"""
Interactive shell session module using Paramiko.

Provides a persistent interactive shell for handling cryptroot-unlock
and other interactive SSH commands with pattern matching support.
"""

import re
import socket
import threading
import time
from typing import Optional, Pattern, Union

import paramiko


class SessionClosedError(Exception):
    """Raised when the session is closed by the remote end."""
    pass


class ExpectTimeoutError(Exception):
    """Raised when expect() times out waiting for a pattern."""
    pass


class InteractiveShellSession:
    """
    Interactive shell session using Paramiko's invoke_shell().
    
    Provides pattern matching (expect) and send functionality for
    handling interactive CLI tools like cryptroot-unlock.
    """
    
    DEFAULT_TIMEOUT = 30.0
    READ_BUFFER_SIZE = 4096
    READ_DELAY = 0.05
    
    def __init__(self, client: paramiko.SSHClient, timeout: float = 10.0):
        """
        Initialize interactive shell session.
        
        Args:
            client: Connected Paramiko SSHClient instance
            timeout: Default timeout for socket operations
        """
        self.client = client
        self.timeout = timeout
        self.channel = None
        self._buffer = ""
        self._lock = threading.Lock()
        self._closed = False
        self._read_thread: Optional[threading.Thread] = None
        self._running = False
    
    def open(self) -> None:
        """Open the interactive shell session."""
        if self.channel is not None:
            return
        
        self.channel = self.client.invoke_shell(
            term='xterm-color',
            width=200,
            height=24
        )
        self.channel.settimeout(self.timeout)
        self.channel.setblocking(False)
        
        self._running = True
        self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._read_thread.start()
        
        time.sleep(0.2)
    
    def _read_loop(self) -> None:
        """Background thread that continuously reads from the channel."""
        while self._running:
            try:
                if self.channel is None or self.channel.closed:
                    break
                
                data = self.channel.recv(self.READ_BUFFER_SIZE)
                if not data:
                    self._closed = True
                    break
                
                decoded = data.decode('utf-8', errors='replace')
                
                with self._lock:
                    self._buffer += decoded
                    
            except socket.timeout:
                continue
            except EOFError:
                self._closed = True
                break
            except OSError:
                self._closed = True
                break
            except Exception:
                self._closed = True
                break
            
            time.sleep(self.READ_DELAY)
    
    def expect(
        self,
        pattern: Union[str, Pattern[str]],
        timeout: float = DEFAULT_TIMEOUT
    ) -> str:
        """
        Read buffer until pattern is found or timeout.
        
        Args:
            pattern: Regex pattern to wait for (string or compiled regex)
            timeout: Maximum seconds to wait for pattern
            
        Returns:
            All accumulated output from start of wait until pattern found
            
        Raises:
            ExpectTimeoutError: If pattern not found within timeout
            SessionClosedError: If session is closed by remote
        """
        if self._closed:
            raise SessionClosedError("Session is closed")
        
        if isinstance(pattern, str):
            pattern = re.compile(pattern, re.IGNORECASE)
        
        start_time = time.time()
        matched_output = ""
        
        while True:
            if self._closed:
                raise SessionClosedError("Session closed while waiting for pattern")
            
            with self._lock:
                match = pattern.search(self._buffer)
                if match:
                    matched_output = self._buffer
                    return matched_output
            
            elapsed = time.time() - start_time
            if elapsed >= timeout:
                with self._lock:
                    matched_output = self._buffer
                raise ExpectTimeoutError(
                    f"Timeout after {timeout}s waiting for pattern: {pattern.pattern}. "
                    f"Output so far: {matched_output[-500:]}"
                )
            
            time.sleep(self.READ_DELAY)
    
    def send(self, data: str) -> None:
        """Send data to the shell.
        
        Args:
            data: String to send (newline is NOT automatically added)
            
        Raises:
            SessionClosedError: If session is closed
        """
        if self._closed or self.channel is None or self.channel.closed:
            raise SessionClosedError("Cannot send to closed session")
        
        self.channel.send(data.encode('utf-8'))
    
    def sendline(self, data: str) -> None:
        """
        Send data followed by newline.
        
        Args:
            data: String to send
        """
        self.send(data + "\n")
    
    def get_buffer(self) -> str:
        """Return current buffer contents."""
        with self._lock:
            return self._buffer
    
    def clear_buffer(self) -> None:
        """Clear the internal buffer."""
        with self._lock:
            self._buffer = ""
    
    def is_alive(self) -> bool:
        """Check if session is still connected."""
        return (
            self.channel is not None
            and not self.channel.closed
            and not self._closed
        )
    
    def wait_for_close(self, timeout: float = 10.0) -> bool:
        """
        Wait for session to be closed by remote end.
        
        Args:
            timeout: Maximum seconds to wait
            
        Returns:
            True if session closed gracefully, False if timeout
        """
        start_time = time.time()
        
        while self.is_alive():
            if time.time() - start_time >= timeout:
                return False
            time.sleep(0.1)
        
        return True
    
    def close(self) -> None:
        """Close the session gracefully."""
        self._running = False
        self._closed = True
        
        if self.channel is not None:
            try:
                self.channel.close()
            except Exception:
                pass
            self.channel = None
    
    def __enter__(self) -> 'InteractiveShellSession':
        """Context manager entry."""
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()
