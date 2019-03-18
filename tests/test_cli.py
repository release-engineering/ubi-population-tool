from ubipop.cli import main
import pytest
import mock


@pytest.fixture()
def mock_ubipopulate():
    with mock.patch('ubipop.UbiPopulate') as mocked_ubipopulate:
        yield mocked_ubipopulate


def test_help():
    args = ['--help']
    with pytest.raises(SystemExit) as e_info:
        main(args)

    assert e_info.value.code == 0


def test_no_pulp_hostname(capsys):
    args = ['--user', 'foo', '--pass', 'foo']

    with pytest.raises(SystemExit) as e_info:
        main(args)

    _, err = capsys.readouterr()
    assert "argument --pulp-hostname is required" in err
    assert e_info.value.code == 2


@pytest.mark.parametrize('auth_args',
                       [(['--user', 'foo', '--pass', 'foo', '--cert', 'foo/cert.cert']),
                        (['--pass', 'foo', '--cert', 'foo/cert.cert']),
                        (['--user', 'foo', '--cert', 'foo/cert.cert']),
                        (['--user', 'foo']),
                        (['--pass', 'foo']),
                        ([]),
                        ])
def test_wrong_user_pass_cert_combination(capsys, auth_args):
    args = ['--pulp-hostname', 'foo.pulp.com'] + auth_args

    with pytest.raises(SystemExit) as e_info:
        main(args)

    _, err = capsys.readouterr()
    assert "Provide --user and --password options or --cert" in err
    assert e_info.value.code == 2


@mock.patch('ubipop.UbiPopulate')
def test_default_config_source(mock_ubipopulate):
    args = ['--pulp-hostname', 'foo.pulp.com', '--user', 'foo', '--pass', 'foo']
    main(args)
    mock_ubipopulate.assert_called_once_with('foo.pulp.com', ('foo', 'foo'), False, [], None,
                                             False, 4)


@mock.patch('ubipop.UbiPopulate')
def test_custom_config_source(mock_ubipopulate):
    args = ['--pulp-hostname', 'foo.pulp.com', '--user', 'foo', '--pass', 'foo', '--conf-src',
            'custom/conf/dir']
    main(args)
    mock_ubipopulate.assert_called_once_with('foo.pulp.com', ('foo', 'foo'), False, [],
                                             'custom/conf/dir', False, 4)

@mock.patch('ubipop.UbiPopulate')
def test_crt(mock_ubipopulate):
    args = ['--pulp-hostname', 'foo.pulp.com', '--cert', '/cert.cert', '--conf-src',
            'custom/conf/dir']
    main(args)
    mock_ubipopulate.assert_called_once_with('foo.pulp.com', ('/cert.cert', ), False, [],
                                             'custom/conf/dir', False, 4)


@mock.patch('ubipop.UbiPopulate')
def test_specified_filenames(mock_ubipopulate):
    args = ['--pulp-hostname', 'foo.pulp.com', '--user', 'foo', '--pass', 'foo', '--conf-src',
            'custom/conf/dir', 'f1', 'f2']
    main(args)
    mock_ubipopulate.assert_called_once_with('foo.pulp.com', ('foo', 'foo'), False, ['f1', 'f2'],
                                             'custom/conf/dir', False, 4)


@mock.patch('ubipop.UbiPopulate')
def test_dry_run(mock_ubipopulate):
    args = ['--pulp-hostname', 'foo.pulp.com', '--user', 'foo', '--pass', 'foo', '--conf-src',
            'custom/conf/dir', 'f1', 'f2', '--dry-run']
    main(args)
    mock_ubipopulate.assert_called_once_with('foo.pulp.com', ('foo', 'foo'), True, ['f1', 'f2'],
                                             'custom/conf/dir', False, 4)


@mock.patch('ubipop.UbiPopulate')
def test_custom_workers_number(mock_ubipopulate):
    args = ['--pulp-hostname', 'foo.pulp.com', '--user', 'foo', '--pass', 'foo', '--conf-src',
            'custom/conf/dir', 'f1', 'f2', '--workers', '42']
    main(args)
    mock_ubipopulate.assert_called_once_with('foo.pulp.com', ('foo', 'foo'), False, ['f1', 'f2'],
                                             'custom/conf/dir', False, 42)

@mock.patch('ubipop.UbiPopulate')
def test_insecure(mock_ubipopulate):
    args = ['--pulp-hostname', 'foo.pulp.com', '--user', 'foo', '--pass', 'foo', '--conf-src',
            'custom/conf/dir', 'f1', 'f2', '--workers', '42', '--insecure']
    main(args)
    mock_ubipopulate.assert_called_once_with('foo.pulp.com', ('foo', 'foo'), False, ['f1', 'f2'],
                                             'custom/conf/dir', True, 42)
