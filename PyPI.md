# ds-protocol-http-py-lib

A Python package from the ds-common library collection.

## Installation

Install the package using pip:

```bash
pip install ds-protocol-http-py-lib
```

Or using uv (recommended):

```bash
uv pip install ds-protocol-http-py-lib
```

## Quick Start

```python
from ds_protocol_http_py_lib import __version__

print(f"ds-protocol-http-py-lib version: {__version__}")
```

## Usage

### Read from a static URL

```python
import uuid
from ds_protocol_http_py_lib.dataset.http import HttpDataset, HttpDatasetSettings
from ds_protocol_http_py_lib.enums import AuthType, HttpMethod
from ds_protocol_http_py_lib.linked_service import OAuth2AuthSettings
from ds_protocol_http_py_lib.linked_service.http import HttpLinkedService, HttpLinkedServiceSettings

linked_service = HttpLinkedService(
    id=uuid.uuid4(),
    name="my-linked-service",
    version="1.0.0",
    settings=HttpLinkedServiceSettings(
        host="https://api.example.com",
        auth_type=AuthType.OAUTH2,
        oauth2=OAuth2AuthSettings(
            token_endpoint="https://api.example.com/oauth/token",
            client_id="my-client",
            client_secret="my-secret",
        ),
    ),
)

dataset = HttpDataset(
    id=uuid.uuid4(),
    name="my-dataset",
    version="1.0.0",
    linked_service=linked_service,
    settings=HttpDatasetSettings(
        method=HttpMethod.GET,
        url="https://api.example.com/data",
    ),
)

linked_service.connect()
dataset.read()
df = dataset.output
```

### Read from a URL with path parameters

Use `{param}` placeholders in the URL and supply their values via `path_params`:

```python
dataset = HttpDataset(
    id=uuid.uuid4(),
    name="my-dataset",
    version="1.0.0",
    linked_service=linked_service,
    settings=HttpDatasetSettings(
        method=HttpMethod.GET,
        url="https://api.example.com/documents/{document_guid}/original",
        path_params={"document_guid": "abc123"},
    ),
)

linked_service.connect()
dataset.read()
df = dataset.output
# Request is sent to: https://api.example.com/documents/abc123/original
```

## Requirements

- Python 3.11 or higher

## Documentation

Full documentation is available at:

- [GitHub Repository](https://github.com/grasp-labs/ds-protocol-http-py-lib)
- [Documentation Site](https://grasp-labs.github.io/ds-protocol-http-py-lib/)

## Development

To contribute or set up a development environment:

```bash
# Clone the repository
git clone https://github.com/grasp-labs/ds-protocol-http-py-lib.git
cd ds-protocol-http-py-lib

# Install development dependencies
uv sync --all-extras --dev

# Run tests
make test
```

See the [README](https://github.com/grasp-labs/ds-protocol-http-py-lib#readme)
for more information.

## License

This package is licensed under the Apache License 2.0.
See the [LICENSE-APACHE](https://github.com/grasp-labs/ds-protocol-http-py-lib/blob/main/LICENSE-APACHE)
file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/grasp-labs/ds-protocol-http-py-lib/issues)
- **Releases**: [GitHub Releases](https://github.com/grasp-labs/ds-protocol-http-py-lib/releases)
