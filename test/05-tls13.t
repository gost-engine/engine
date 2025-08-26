#!/usr/bin/perl
use strict;
use warnings;
use Test2::V0;
use Cwd 'abs_path';
use FindBin;
use lib "$FindBin::Bin";
use File::Temp qw(tempfile);
use JSON::PP;
use ProcessInteractor;
use Utils;

skip_all('Only for provider') unless $ARGV[0] eq 'provider';
skip_all('Enable with GOST_PROVIDER_ENABLE_ONLINE_TESTS=1')
  unless $ENV{GOST_PROVIDER_ENABLE_ONLINE_TESTS};

skip_all('Test skipped. Use patched openssl to run the test. Set env variable TLS13_PATCHED_OPENSSL to run the test.')
    unless $ENV{TLS13_PATCHED_OPENSSL};

my $openssl_bin = $ENV{OPENSSL_PROGRAM} || "openssl";
my $run_extended = $ENV{GOST_TEST_RUN_EXTENDED} || 0;

my $config_dir = abs_path("$FindBin::Bin/tls13-configs");
my @tests = make_test_plan($config_dir);

unless ($run_extended) {
    note("Set GOST_TEST_RUN_EXTENDED=1 to run all combinations in the test");
    @tests = ($tests[rand @tests]);
}

plan tests => scalar @tests;

for my $t (@tests) {
    my @cmd = (
        $openssl_bin, "s_client",
        "-connect", "$t->{host}:$t->{port}", "-tls1_3", "-no_ign_eof",
        "-ciphersuites", $t->{ciphersuite},
        "-curves", $t->{curve},
        "-sigalgs", $t->{sigalg},
        "-CAfile", $t->{ca},
        "-servername", $t->{servername}
    );

    if ($t->{use_auth}) {
        push @cmd,
          (
            "-cert", $t->{cert}, "-key", $t->{key}, "-client_sigalgs",
            $t->{client_sigalg},
          );
    }

    my $cmdline = join(" ", @cmd);
    note($cmdline);

    my ($status, $output, $rc, $success) = (ProcessInteractor::STATUS_OK, '', -1, 0);
    my $command = "HEAD / HTTP/1.1\r\nHost: $t->{servername}\r\n\r\n";
    if (not $t->{use_auth} or $t->{expect_auth_success}) {
        ($status, $output, $rc) = run_sclient($cmdline, $command, 30, 0);
        $success = (($status == ProcessInteractor::STATUS_OK) and ($rc == 0));
    }
    else {
        # Infotecs test certificates expire on 2025-12-09. After that we've got to set
        # expect_auth_success=false in the config.
        ($status, $output, $rc) = run_sclient($cmdline, $command, 1, 1);
        $success = (($status == ProcessInteractor::STATUS_OK)
              and ($output =~ /Connection: close/m));
    }
    my $info = "TLS1.3 to $t->{host}:$t->{port} ciphersuite=$t->{ciphersuite}"
        ." group=$t->{curve} sigalg=$t->{sigalg}: status=@{[ProcessInteractor::status_str($status)]}, rc=$rc";
    is($success, 1, $info) or diag($output);
}

sub end_on_blank {
    my ($response) = @_;
    return $response =~ /\r\n\r\n/m;
}

sub end_on_verify_return_code {
    my ($response) = @_;
    return $response =~ /Verify return code[^\n]*\n---\n/m;
}

sub run_sclient {
    my ($cmdline, $command, $iterations, $server_closes_connection) = @_;

    my $proc = ProcessInteractor->new(
        cmdline => $cmdline,
        start_timeout => 30,
        read_timeout => 5,
        exit_timeout => 1
    );
    my ($status, $out) = $proc->start(\&end_on_verify_return_code);
    return ($status, $out, 1) if $status != ProcessInteractor::STATUS_OK;

    my $resp;
    for my $i (1 .. $iterations) {
        ($status, $resp) = $proc->interact($command, \&end_on_blank);
        $out .= $resp;
        return ($status, $out, 1) if $status != ProcessInteractor::STATUS_OK;
    }

    unless ($server_closes_connection) {
        $proc->close_stdin();
    }

    (undef, $resp, my $exitcode) = $proc->wait_for_exit();
    $out .= $resp;
    return (ProcessInteractor::STATUS_OK, $out, $exitcode);
}

sub read_file {
    my ($path) = @_;
    open my $fh, '<', $path;
    local $/;
    return <$fh>;
}

sub write_temp_file {
    my ($data, $suffix, $template) = @_;
    my ($fh, $filename) = tempfile(
        TEMPLATE => ($template || "tls13_$$\_" . time . "_XXXXXXXX"),
        DIR => "$FindBin::Bin",
        SUFFIX => $suffix,
        UNLINK => 1,
    );
    binmode($fh, ":utf8");
    print $fh $data;
    close $fh;
    return $filename;
}

sub load_endpoint_tests {
    my ($conf) = @_;
    my @tests;

    if ($conf->{skip} == 1) {
        return @tests;
    }

    my $host = $conf->{host};
    my $servername = $conf->{servername} // $host;
    my $ca_path = write_temp_file(join("\n", @{$conf->{ca}}),
        '.pem', "tls13_" . $servername . "_ca_XXXX");
    my @users = @{$conf->{user} // []};

    for my $user (@users) {
        my $user_sigalg = $user->{sigalg};
        my $cert = join("\n", @{$user->{cert}});
        my $key = join("\n", @{$user->{key}});
        $user->{cert_file} = write_temp_file($cert, '.pem',
            "tls13_" . $servername . "_usercert_" . $user_sigalg . "_XXXX");
        $user->{key_file} = write_temp_file($key, '.pem',
            "tls13_" . $servername . "_userkey_" . $user_sigalg . "_XXXX");
    }

    srand(time ^ $$);

    for my $ep (@{$conf->{endpoints}}) {
        my $port = $ep->{port} // 443;
        my $auth = $ep->{auth} // $conf->{auth} // 0;
        my $join_sigalgs = $ep->{join_sigalgs} // $conf->{join_sigalgs} // 0;
        my $expect_auth_success = $ep->{expect_auth_success} // $conf->{expect_auth_success} // $auth;
        my @ciphersuites = @{$ep->{ciphersuites} // $conf->{ciphersuites}};
        my @curves = @{$ep->{curves} // $conf->{curves}};
        my @sigalgs = @{$ep->{sigalgs} // $conf->{sigalgs}};
        my @supported_client_sigalgs = @{$ep->{supported_client_sigalgs} // $conf->{supported_client_sigalgs}};

        if ($join_sigalgs) {
            @sigalgs = (join(":", @sigalgs));
        }

        my $it;
        if ($auth) {
            $it = Utils::cartesian_product_iterator(\@ciphersuites,
                \@curves, \@sigalgs, \@users);
        }
        else {
            $it = Utils::cartesian_product_iterator(\@ciphersuites,
                \@curves, \@sigalgs);
        }

        my @ep_tests;
        while (my $combination = $it->()) {
            my ($ciphersuite, $curve, $sigalg, $user) = @$combination;

            my ($user_cert, $user_key, $user_sigalg);
            if (defined($user)) {
                $user_sigalg = $user->{sigalg};
                unless (grep { $_ eq $user_sigalg } @supported_client_sigalgs) {
                    next;
                }
                $user_cert = $user->{cert_file};
                $user_key = $user->{key_file};
            }

            push @ep_tests,
              {
                host => $host,
                port => $port,
                ciphersuite => $ciphersuite,
                curve => $curve,
                client_sigalg => $user_sigalg,
                sigalg => $sigalg,
                servername => $servername,
                ca => $ca_path,
                cert => $user_cert,
                key => $user_key,
                use_auth => $auth,
                expect_auth_success => $expect_auth_success,
              };
        }

        if (@ep_tests) {
            push @tests, @ep_tests;
        }
    }

    return @tests;
}

sub make_test_plan {
    my ($config_dir) = @_;

    opendir(my $dh, $config_dir)
      or skip_all("Directory $config_dir is not found");
    my @config_files = grep { /\.json$/ && -f "$config_dir/$_" } readdir($dh);
    closedir($dh);
    skip_all("Directory $config_dir has no test configs") unless @config_files;

    my @tests;
    for my $config_file (@config_files) {
        my $data = read_file("$config_dir/$config_file");
        my $config = JSON::PP->new->utf8->decode($data);
        for my $server (@$config) {
            push @tests, load_endpoint_tests($server);
        }
    }

    return @tests;
}
