"""Settings resolution: CLI flags over the process environment over the env file over defaults."""

import pytest

from oauthenticator.cli import parse_args

REQUIRED_FLAGS = ['--issuer', 'https://issuer.test', '--client-id', 'cli-client']


@pytest.fixture
def env_file(tmp_path):
    path = tmp_path / 'settings.env'
    path.write_text('OAUTHENTICATOR_ISSUER=https://file.test\n'
                    'OAUTHENTICATOR_CLIENT_ID=file-client\n'
                    'OAUTHENTICATOR_CLIENT_SECRET=file-secret\n')

    return path


def test_reads_everything_from_the_env_file(env_file):
    config = parse_args(['--env-file', str(env_file)], environ={})

    assert config.issuer == 'https://file.test'
    assert config.client_id == 'file-client'
    assert config.client_secret == 'file-secret'


def test_process_environment_beats_the_env_file(env_file):
    environ = {'OAUTHENTICATOR_ISSUER': 'https://process.test'}

    config = parse_args(['--env-file', str(env_file)], environ=environ)

    assert config.issuer == 'https://process.test'
    assert config.client_id == 'file-client'


def test_cli_flag_beats_the_process_environment(env_file):
    environ = {'OAUTHENTICATOR_CLIENT_SECRET': 'process-secret'}

    config = parse_args(['--env-file', str(env_file), '--client-secret', 'cli-secret'],
                        environ=environ)

    assert config.client_secret == 'cli-secret'


def test_empty_variable_hides_the_env_file_value(env_file):
    config = parse_args(['--env-file', str(env_file)], environ={'OAUTHENTICATOR_CLIENT_SECRET': ''})

    assert config.client_secret is None


def test_empty_variable_falls_back_to_the_default():
    config = parse_args(REQUIRED_FLAGS, environ={'OAUTHENTICATOR_PORT': ''})

    assert config.redirect_uri == 'http://localhost:8765/callback'


def test_variables_without_the_prefix_are_ignored():
    config = parse_args(REQUIRED_FLAGS, environ={'CLIENT_SECRET': 'foreign-secret'})

    assert config.client_secret is None


def test_reads_dot_env_from_the_current_directory(tmp_path, monkeypatch):
    (tmp_path / '.env').write_text('OAUTHENTICATOR_ISSUER=https://cwd.test\n'
                                   'OAUTHENTICATOR_CLIENT_ID=cwd-client\n')
    monkeypatch.chdir(tmp_path)

    config = parse_args([], environ={})

    assert config.issuer == 'https://cwd.test'


def test_missing_default_env_file_is_skipped(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    config = parse_args(REQUIRED_FLAGS, environ={})

    assert config.issuer == 'https://issuer.test'


def test_missing_explicit_env_file_is_an_error(tmp_path):
    with pytest.raises(SystemExit):
        parse_args([*REQUIRED_FLAGS, '--env-file', str(tmp_path / 'absent.env')], environ={})


def test_issuer_is_required_from_some_source(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit):
        parse_args(['--client-id', 'cli-client'], environ={})

    assert 'OAUTHENTICATOR_ISSUER' in capsys.readouterr().err


def test_help_never_shows_the_secret(capsys):
    with pytest.raises(SystemExit):
        parse_args(['--help'], environ={'OAUTHENTICATOR_CLIENT_SECRET': 'process-secret'})

    assert 'process-secret' not in capsys.readouterr().out


def test_env_add_scope_comes_before_cli_add_scope():
    environ = {'OAUTHENTICATOR_ADD_SCOPE': 'offline_access groups'}

    config = parse_args([*REQUIRED_FLAGS, '--add-scope', 'roles'], environ=environ)

    assert config.scope == 'openid email profile offline_access groups roles'


def test_env_scope_replaces_the_default():
    config = parse_args(REQUIRED_FLAGS, environ={'OAUTHENTICATOR_SCOPE': 'openid'})

    assert config.scope == 'openid'


def test_redirect_uri_defaults_to_localhost_8765():
    config = parse_args(REQUIRED_FLAGS, environ={})

    assert config.redirect_uri == 'http://localhost:8765/callback'


def test_redirect_uri_is_built_from_host_and_port():
    environ = {'OAUTHENTICATOR_HOST': '127.0.0.1'}

    config = parse_args([*REQUIRED_FLAGS, '--port', '9000'], environ=environ)

    assert config.redirect_uri == 'http://127.0.0.1:9000/callback'


def test_explicit_redirect_uri_wins_over_host_and_port(capsys):
    environ = {'OAUTHENTICATOR_REDIRECT_URI': 'http://localhost:7000/cb'}

    config = parse_args([*REQUIRED_FLAGS, '--port', '9000'], environ=environ)

    assert config.redirect_uri == 'http://localhost:7000/cb'
    assert 'ignored' in capsys.readouterr().err


def test_non_numeric_env_port_is_an_error():
    with pytest.raises(SystemExit):
        parse_args(REQUIRED_FLAGS, environ={'OAUTHENTICATOR_PORT': 'eighty'})
