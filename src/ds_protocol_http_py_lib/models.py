"""
**File:** ``models.py``
**Region:** ``ds_protocol_http_py_lib``

Typed helper models used by the HTTP dataset layer.
"""

from dataclasses import dataclass

from ds_common_serde_py_lib import Serializable


@dataclass(kw_only=True)
class Files(Serializable):
    """
    Multipart file descriptor for `HttpDatasetSettings.files`.
    """

    field: str = "file"
    """Multipart form field name (e.g. ``"file"`` or ``"upload"``)."""

    filename: str
    """Filename sent as the multipart part name."""

    content: bytes | str
    """File payload sent as multipart file content."""

    content_type: str | None = None
    """Optional content-type for the multipart part."""

    def to_requests_file_tuple(
        self,
    ) -> tuple[str, bytes | str] | tuple[str, bytes | str, str]:
        """
        Convert into a `requests` multipart file tuple.

        Tuple shapes supported by `requests`:
        - ``(filename, fileobj)``
        - ``(filename, fileobj, content_type)``
        """
        if self.content_type is not None:
            return (self.filename, self.content, self.content_type)
        return (self.filename, self.content)
