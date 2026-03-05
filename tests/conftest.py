"""Shared test fixtures for mipiti-verify tests."""

from pathlib import Path

import pytest


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    """Create a temporary project root with common test files."""
    return tmp_path


@pytest.fixture
def python_file(project_root: Path) -> Path:
    """Create a sample Python file."""
    f = project_root / "app.py"
    f.write_text(
        '''import os
from hashlib import sha256

class AuthService:
    """Authentication service."""

    @require_auth
    def validate_input(self, data: str) -> bool:
        """Validate input data length."""
        try:
            if len(data) > 1000:
                raise ValueError("Input too long")
            return True
        except ValueError as e:
            return False

    def check_password(self, password: str) -> bool:
        """Check password strength."""
        return len(password) >= 8

def process_request(request):
    """Process an API request."""
    validate_input(request.body)
    return {"status": "ok"}
''',
        encoding="utf-8",
    )
    return f


@pytest.fixture
def js_file(project_root: Path) -> Path:
    """Create a sample JavaScript file."""
    f = project_root / "server.js"
    f.write_text(
        '''const express = require('express');
const helmet = require('helmet');

const app = express();
app.use(helmet());

function handleAuth(req, res) {
    try {
        const token = req.headers['authorization'];
        if (!token) {
            res.set('X-Frame-Options', 'DENY');
            return res.status(401).json({ error: 'Unauthorized' });
        }
    } catch(err) {
        return res.status(500).json({ error: 'Internal error' });
    }
}

module.exports = { handleAuth };
''',
        encoding="utf-8",
    )
    return f


@pytest.fixture
def config_json(project_root: Path) -> Path:
    """Create a sample JSON config."""
    f = project_root / "config.json"
    f.write_text(
        '{"database": {"host": "localhost", "port": 5432}, "debug": false, "secret_key": "changeme"}',
        encoding="utf-8",
    )
    return f


@pytest.fixture
def env_file(project_root: Path) -> Path:
    """Create a sample .env file."""
    f = project_root / ".env"
    f.write_text(
        "DATABASE_URL=postgres://localhost:5432/mydb\nSECRET_KEY=changeme\nDEBUG=false\n",
        encoding="utf-8",
    )
    return f


@pytest.fixture
def requirements_txt(project_root: Path) -> Path:
    """Create a sample requirements.txt."""
    f = project_root / "requirements.txt"
    f.write_text(
        "flask>=2.0\nrequests==2.31.0\npydantic>=2.0,<3.0\ncryptography\n",
        encoding="utf-8",
    )
    return f


@pytest.fixture
def package_json(project_root: Path) -> Path:
    """Create a sample package.json."""
    f = project_root / "package.json"
    f.write_text(
        '{"name": "myapp", "dependencies": {"express": "^4.18.0", "helmet": "^7.0.0"}, "devDependencies": {"jest": "^29.0.0"}}',
        encoding="utf-8",
    )
    return f
