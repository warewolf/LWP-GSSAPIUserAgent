package LWP::GSSAPIUserAgent;
use MIME::Base64 "2.12";
use GSSAPI 0.18;
use LWP::Debug;
use base qw(LWP::UserAgent);
our $VERSION = "0.1.0";

# This code largely ripped from LWP::Authen::Negotiate.

sub request {
  my($self, $request, $arg, $size, $previous) = @_;
  my $uri = URI->new($request->uri);
  my $targethost = $request->uri()->host();
  my $auth_header = defined ($self->proxy($uri->scheme())) ? 'Proxy-Authorization' : 'Authorization';
  my ($otoken,$status,$target,$tname);

  $status = GSSAPI::Name->import(
    $target,
    join( '@', 'HTTP', $targethost ),
    GSSAPI::OID::gss_nt_hostbased_service
  );

  $status  = $target->display( $tname );

  LWP::Debug::debug("GSSAPI servicename $tname");
  my $itoken = q{};

  my $ctx = GSSAPI::Context->new();
  my $imech = GSSAPI::OID::gss_mech_krb5;

  my $iflags = GSS_C_REPLAY_FLAG;
  if ( $ENV{LWP_AUTHEN_NEGOTIATE_DELEGATE} ) {
  $iflags =    $iflags
          | GSS_C_MUTUAL_FLAG
          | GSS_C_DELEG_FLAG;
  }
  my $bindings = GSS_C_NO_CHANNEL_BINDINGS;
  my $creds    = GSS_C_NO_CREDENTIAL;
  my $itime    = 0;
  #
  # let's go with init_security_context!
  #
  $status = $ctx->init( $creds, $target,
                  $imech, $iflags, $itime , $bindings,$itoken,
                  undef, $otoken, undef, undef);
  if  (    $status->major == GSS_S_COMPLETE
  or $status->major == GSS_S_CONTINUE_NEEDED   ) {
    # Kerb init success, add in the Auth header
    LWP::Debug::debug( 'successfull $ctx->init()');
    my $referral = $request->clone;
    $referral->header( $auth_header => "Negotiate ".encode_base64($otoken,""));
    return $self->SUPER::request( $referral, $arg, $size, $previous);
  } else {
    # kerb failed, don't try to send auth
    LWP::Debug::debug( 'failed $ctx->init(), falling through to skipping auth');
    return $self->SUPER::request( $request, $arg, $size, $previous );
  }
}

1

__END__

=pod

=head1 NAME

LWP::GSSAPIUserAgent - A sub-class of LWP::UserAgent that tries to Do The Right Thing[tm], w/ kerberized services

=head1 SYNOPSIS

  use LWP::GSSAPIUserAgent;

  my $ua = LWP::GSSAPIUserAgent;
  my $request = $ua->request(...)

=head1 USAGE

Do ths right thing with Kerberos HTTP services.  This module will attempt to establish a kerberos ticket for the HTTP service, if possible, and then re-use it in later requests.  This should reduce the number of 401 UNAUTHORIZED requests to Kerberos services via LWP.

See L<the LWP::UserAgent request method|LWP::UserAgent> documentation for details.  This module simply wraps it, adding in the required C<Proxy-Authorization> or C<Authorization> header if possible.



=head1 SEE ALSO

=over

=item http://search.cpan.org/perldoc?LWP%3A%3AAuthen%3A%3ANegotiate

The LWP::Authen::Negotiate module, which this module is essentially a reimplementation of.

=head1 AUTHOR



=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006 by Achim Grolms <perl@grolmsnet.de>

Copyright (C) 2-15 by Richard Harman <perl-cpan@richardharman.com>

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.4 or,
at your option, any later version of Perl 5 you may have available.

=cut


