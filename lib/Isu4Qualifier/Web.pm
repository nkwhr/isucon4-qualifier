package Isu4Qualifier::Web;

use strict;
use warnings;
use utf8;
use Kossy;
# use DBIx::Sunny;
use Digest::SHA qw/ sha256_hex /;
# use Data::Dumper;
use Redis::Fast;
use Time::Piece;

sub config {
  my ($self) = @_;
  $self->{_config} ||= {
    user_lock_threshold => $ENV{'ISU4_USER_LOCK_THRESHOLD'} || 3,
    ip_ban_threshold => $ENV{'ISU4_IP_BAN_THRESHOLD'} || 10
  };
};

# sub db {
#   my ($self) = @_;
#   my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
#   my $port = $ENV{ISU4_DB_PORT} || 3306;
#   my $username = $ENV{ISU4_DB_USER} || 'root';
#   my $password = $ENV{ISU4_DB_PASSWORD};
#   my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

#   $self->{_db} ||= do {
#     DBIx::Sunny->connect(
#       "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
#         RaiseError => 1,
#         PrintError => 0,
#         AutoInactiveDestroy => 1,
#         mysql_enable_utf8   => 1,
#         mysql_auto_reconnect => 1,
#       },
#     );
#   };
# }

sub redis {
    my $self = shift;
    $self->{_redis} ||= do {
      Redis::Fast->new(sock => '/tmp/redis.sock');
    };
}

sub calculate_password_hash {
  my ($password, $salt) = @_;
  sha256_hex($password . ':' . $salt);
};

sub user_locked {
  my ($self, $user_id) = @_;

  my $count = $self->redis->zscore('failure:id', $user_id) || 0;
  $self->config->{user_lock_threshold} <= $count;

  # my $log = $self->db->select_row(
  #   'SELECT COUNT(1) AS failures FROM login_log WHERE user_id = ? AND id > IFNULL((select id from login_log where user_id = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)',
  #   $user->{'id'}, $user->{'id'});

  # $self->config->{user_lock_threshold} <= $log->{failures};
};

sub ip_banned {
  my ($self, $ip) = @_;

  my $count = $self->redis->zscore('failure:ip', $ip) || 0;
  $self->config->{ip_ban_threshold} <= $count;

  # my $log = $self->db->select_row(
  #   'SELECT COUNT(1) AS failures FROM login_log WHERE ip = ? AND id > IFNULL((select id from login_log where ip = ? AND succeeded = 1 ORDER BY id DESC LIMIT 1), 0)',
  #   $ip, $ip);

  # $self->config->{ip_ban_threshold} <= $log->{failures};
};

sub attempt_login {
  my ($self, $login, $password, $ip) = @_;
  # my $user = $self->db->select_row('SELECT * FROM users WHERE login = ?', $login);
  my $user_id = $self->redis->get("login:$login");

  if ($self->ip_banned($ip)) {
    $self->redis->zincrby('failure:ip', 1, $ip);
    $self->redis->zincrby('failure:id', 1, $user_id) if $user_id;
    # $self->login_log(0, $login, $ip, $user ? $user->{id} : undef);
    return undef, 'banned';
  }

  if ($self->user_locked($user_id)) {
    $self->redis->zincrby('failure:ip', 1, $ip);
    $self->redis->zincrby('failure:id', 1, $user_id);
    # $self->login_log(0, $login, $ip, $user->{id});
    return undef, 'locked';
  }

  my %user = $self->redis->hgetall("user:$user_id");

  if ($user_id && calculate_password_hash($password, $user{salt}) eq $user{password_hash}) {
    my $log = {
      created_at => Time::Piece::localtime->strftime('%Y-%m-%d %H:%M:%S'),
      user_id    => $user_id,
      login      => $user{login},
      ip         => $ip,
    };
    $self->redis->hmset('last_login:' . $user_id, %$log);
    $self->redis->zrem('failure:ip', $ip);
    $self->redis->zrem('failure:id', $user_id);
    # $self->login_log(1, $login, $ip, $user->{id});
    return \%user, undef;
  }
  elsif ($user_id) {
    $self->redis->zincrby('failure:ip', 1, $ip);
    $self->redis->zincrby('failure:id', 1, $user_id);
    # $self->login_log(0, $login, $ip, $user->{id});
    return undef, 'wrong_password';
  }
  else {
    $self->redis->zincrby('failure:ip', 1, $ip);
    # $self->login_log(0, $login, $ip);
    return undef, 'wrong_login';
  }
};

sub current_user {
  my ($self, $user_id) = @_;

  $self->redis->hget("user:$user_id", 'login') ? 1 : undef;
  # $self->db->select_row('SELECT * FROM users WHERE id = ?', $user_id);
};

sub last_login {
  my ($self, $user_id) = @_;

  my %last_login = $self->redis->hgetall("last_login:$user_id");

  \%last_login;

  # my $logs = $self->db->select_all(
  #  'SELECT * FROM login_log WHERE succeeded = 1 AND user_id = ? ORDER BY id DESC LIMIT 2',
  #  $user_id);

  # @$logs[-1];
};

sub banned_ips {
  my ($self) = @_;
  my @ips;
  my $threshold = $self->config->{ip_ban_threshold};

  @ips = $self->redis->zrangebyscore('failure:ip', $threshold, '+inf');

  # my $not_succeeded = $self->db->select_all('SELECT ip FROM (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?', $threshold);

  # foreach my $row (@$not_succeeded) {
  #   push @ips, $row->{ip};
  # }

  # my $last_succeeds = $self->db->select_all('SELECT ip, MAX(id) AS last_login_id FROM login_log WHERE succeeded = 1 GROUP by ip');

  # foreach my $row (@$last_succeeds) {
  #   my $count = $self->db->select_one('SELECT COUNT(1) AS cnt FROM login_log WHERE ip = ? AND ? < id', $row->{ip}, $row->{last_login_id});
  #   if ($threshold <= $count) {
  #     push @ips, $row->{ip};
  #   }
  # }

  \@ips;
};

sub locked_users {
  my ($self) = @_;
  my @user_ids;
  my $threshold = $self->config->{user_lock_threshold};

  @user_ids = $self->redis->zrangebyscore('failure:id', $threshold, '+inf');

  my @logins;
  for my $user_id (@user_ids) {
    $self->redis->hget("user:$user_id", 'login', sub {
      push @logins, $_[0]
    });
  }
  $self->redis->wait_all_responses;

  \@logins;
  # my $not_succeeded = $self->db->select_all('SELECT user_id, login FROM (SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) AS t0 WHERE t0.user_id IS NOT NULL AND t0.max_succeeded = 0 AND t0.cnt >= ?', $threshold);

  # foreach my $row (@$not_succeeded) {
  #   push @user_ids, $row->{login};
  # }

  # my $last_succeeds = $self->db->select_all('SELECT user_id, login, MAX(id) AS last_login_id FROM login_log WHERE user_id IS NOT NULL AND succeeded = 1 GROUP BY user_id');

  # foreach my $row (@$last_succeeds) {
  #   my $count = $self->db->select_one('SELECT COUNT(1) AS cnt FROM login_log WHERE user_id = ? AND ? < id', $row->{user_id}, $row->{last_login_id});
  #   if ($threshold <= $count) {
  #     push @user_ids, $row->{login};
  #   }
  # }

  #\@user_ids;
};

# sub login_log {
#   my ($self, $succeeded, $login, $ip, $user_id) = @_;
#   $self->db->query(
#     'INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) VALUES (NOW(),?,?,?,?)',
#     $user_id, $login, $ip, ($succeeded ? 1 : 0)
#   );
# };

sub set_flash {
  my ($self, $c, $msg) = @_;
  $c->req->env->{'psgix.session'}->{flash} = $msg;
};

sub pop_flash {
  # my ($self, $c, $msg) = @_;
  my ($self, $c) = @_;
  my $flash = $c->req->env->{'psgix.session'}->{flash};
  delete $c->req->env->{'psgix.session'}->{flash};
  $flash;
};

filter 'session' => sub {
  my ($app) = @_;
  sub {
    my ($self, $c) = @_;
    my $sid = $c->req->env->{'psgix.session.options'}->{id};
    $c->stash->{session_id} = $sid;
    $c->stash->{session}    = $c->req->env->{'psgix.session'};
    $app->($self, $c);
  };
};

get '/' => [qw(session)] => sub {
  my ($self, $c) = @_;

  $c->render('index.tx', { flash => $self->pop_flash($c) });
};

post '/login' => sub {
  my ($self, $c) = @_;
  # my $msg;

  my ($user, $err) = $self->attempt_login(
    $c->req->param('login'),
    $c->req->param('password'),
    $c->req->address
  );

  if ($user && $user->{id}) {
    $c->req->env->{'psgix.session'}->{user_id} = $user->{id};
    $c->redirect('/mypage');
  }
  else {
    if ($err eq 'locked') {
      $self->set_flash($c, 'This account is locked.');
    }
    elsif ($err eq 'banned') {
      $self->set_flash($c, "You're banned.");
    }
    else {
      $self->set_flash($c, 'Wrong username or password');
    }
    $c->redirect('/');
  }
};

get '/mypage' => [qw(session)] => sub {
  my ($self, $c) = @_;

  # my $user_id = $c->req->env->{'psgix.session'}->{user_id};
  # my $user = $self->current_user($user_id);
  # my $msg;

  if (my $user_id = $c->req->env->{'psgix.session'}->{user_id}) {
    return $c->render('mypage.tx', { last_login => $self->last_login($user_id) }) if $self->current_user($user_id);
  }
  # if ($user) {
  #   $c->render('mypage.tx', { last_login => $self->last_login($user_id) });
  # }
  # else {
  #   $self->set_flash($c, "You must be logged in");
  #   $c->redirect('/');
  # }

  $self->set_flash($c, "You must be logged in");
  $c->redirect('/');
};

get '/report' => sub {
  my ($self, $c) = @_;

  $self->redis->bgsave;

  $c->render_json({
    banned_ips => $self->banned_ips,
    locked_users => $self->locked_users,
  });
};

1;
