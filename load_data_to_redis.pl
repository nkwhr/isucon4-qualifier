#!/usr/bin/env perl

use strict;
use warnings;
use DBIx::Sunny;
use Redis::Fast;

my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
my $port = $ENV{ISU4_DB_PORT} || 3306;
my $username = $ENV{ISU4_DB_USER} || 'root';
my $password = $ENV{ISU4_DB_PASSWORD};
my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

my $db = DBIx::Sunny->connect(
  "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
    RaiseError => 1,
    PrintError => 0,
    AutoInactiveDestroy => 1,
    mysql_enable_utf8   => 1,
    mysql_auto_reconnect => 1,
  },
);

my $redis = Redis::Fast->new;

my $logs = $db->select_all('SELECT * FROM login_log ORDER BY id');

for my $log (@$logs) {
  if ($log->{succeeded} == 1) {
    my $log = {
      created_at => $log->{created_at},
      user_id    => $log->{user_id},
      login      => $log->{login},
      ip         => $log->{ip},
    };
    $redis->hmset('last_login:' . $log->{user_id}, %$log, sub {});
    $redis->zrem('failure:ip', $log->{ip}, sub {});
    $redis->zrem('failure:id', $log->{user_id}, sub {});
  }
  else {
    $redis->zincrby('failure:ip', 1, $log->{ip}, sub {});
    $redis->zincrby('failure:id', 1, $log->{user_id}, sub {});
  }
  $redis->wait_all_responses;
}

my $users = $db->select_all('SELECT * FROM users ORDER BY id');

for my $user (@$users) {
  my $user_info = {
      id            => $user->{id},
      login         => $user->{login},
      password_hash => $user->{password_hash},
      salt          => $user->{salt},
  };
  $redis->hmset('user:' . $user->{id}, %$user_info, sub {});
  $redis->set('login:' . $user->{login}, $user->{id}, sub {});
}

$redis->wait_all_responses;
