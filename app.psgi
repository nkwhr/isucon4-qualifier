use FindBin;
use lib "$FindBin::Bin/extlib/lib/perl5";
use lib "$FindBin::Bin/lib";
use File::Basename;
use Plack::Builder;
use Isu4Qualifier::Web;
use Plack::Builder;
use Cache::Memcached::Fast;

my $root_dir = File::Basename::dirname(__FILE__);

my $app = Isu4Qualifier::Web->psgi($root_dir);
builder {
  enable 'ReverseProxy';
  enable 'Static',
    path => qr!^/(?:stylesheets|images)/!,
    root => $root_dir . '/public';
  enable 'Plack::Middleware::Session::Simple',
    store => Cache::Memcached::Fast->new({servers=>[{ address => 'localhost:11211'}]}),
    cookie_name => 'isu4_session',
    expires => '+7d';
  $app;
};
