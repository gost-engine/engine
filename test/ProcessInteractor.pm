# Implemented using ChatGPT
package ProcessInteractor;
use strict;
use warnings;
use IPC::Open3;
use IO::Select;
use POSIX ":sys_wait_h";
use Symbol 'gensym';
use feature "switch";
use constant {
    STATUS_OK => 0,
    STATUS_TIMEOUT => 1,
    STATUS_EOF => 2,
};

sub status_str {
    my ($status) = @_;

    if ($status == STATUS_OK) {
        return "OK";
    }
    elsif ($status == STATUS_TIMEOUT) {
        return "Timeout";
    }
    elsif ($status == STATUS_EOF) {
        return "EOF";
    }
    else {
        return "Unknown";
    }
}

sub new {
    my ($class, %args) = @_;
    my $self = {
        cmdline => ($args{cmdline} || die "cmdline required"),
        start_timeout => ($args{start_timeout} || 1),
        read_timeout => ($args{read_timeout} || 1),
        exit_timeout => ($args{exit_timeout} || 1),
        _pid => undef,
        _reader => undef,
        _writer => undef,
        _err => undef,
        _sel => undef,
    };

    return bless $self, $class;
}

sub _start_process {
    my ($self) = @_;
    my ($reader, $writer, $err);
    $err = gensym;
    my $pid = open3($writer, $reader, $err, "sh -c \'$self->{cmdline} 2>&1\' ")
      or die "Cannot start process: $!";
    my $sel = IO::Select->new($reader);
    $writer->autoflush(1);
    close $err;

    $self->{_pid} = $pid;
    $self->{_reader} = $reader;
    $self->{_writer} = $writer;
    $self->{_sel} = $sel;
}

sub _read_until {
    my ($self, $check_sub, $timeout) = @_;
    my $reader = $self->{_reader} or die "Reader not set";
    my $sel = $self->{_sel} or die "Selector not set";
    my $output = '';

    my $buf;
    while (1) {
        my @ready = $sel->can_read($timeout);
        unless (@ready) {
            return (STATUS_TIMEOUT, $output);
        }

        # Читаем ВСЁ, что доступно прямо сейчас
        while ($sel->can_read(0)) {
            my $bytes_read = sysread($reader, $buf, 4096);
            unless (defined $bytes_read) {
                die "Error reading from process: $!";
            }
            if ($bytes_read == 0) {
                return (STATUS_EOF, $output);
            }
            $output .= $buf;
        }

        if ($check_sub->($output)) {
            return (STATUS_OK, $output);
        }
    }
}

sub start {
    my ($self, $start_check) = @_;
    $start_check ||= sub { 1 };
    die "start_check must be a CODE ref" unless ref $start_check eq 'CODE';

    $self->_start_process();
    my ($status, $output) =
      $self->_read_until($start_check, $self->{start_timeout});
    return ($status, $output);
}

sub interact {
    my ($self, $command, $response_check) = @_;
    die "Process not started" unless defined $self->{_pid};
    $response_check ||= sub { 1 };
    die "response_check must be a CODE ref"
      unless ref $response_check eq 'CODE';

    my $writer = $self->{_writer};
    print $writer "$command";

    my ($status, $response) =
      $self->_read_until($response_check, $self->{read_timeout});
    return ($status, $response);
}

sub close_stdin {
    my ($self) = @_;
    close $self->{_writer};
}

sub wait_for_exit {
    my ($self) = @_;
    die "Process not started" unless defined $self->{_pid};

    my ($status, $output) =
      $self->_read_until(sub { 0 }, $self->{exit_timeout});

    my $exit_timeout = $self->{exit_timeout};
    my $elapsed = 0;
    my $interval = 0.1;
    while ($elapsed < $exit_timeout) {
        my $res = waitpid($self->{_pid}, WNOHANG);
        if ($res > 0) {
            my $exitcode = $? >> 8;
            return ($status, $output, $exitcode);
        }
        select(undef, undef, undef, $interval);
        $elapsed += $interval;
    }

    kill 'TERM', $self->{_pid};
    select(undef, undef, undef, 0.5);
    if (waitpid($self->{_pid}, WNOHANG) == 0) {
        kill 'KILL', $self->{_pid};
        waitpid($self->{_pid}, 0);
    }
    my $exitcode = $? >> 8;
    return ($status, $output, $exitcode);
}

1;
