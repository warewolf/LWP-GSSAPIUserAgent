use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'LWP::GSSAPIUserAgent',
    AUTHOR              => 'Richard <perl-cpan@richardharman.com>',
    VERSION_FROM        => 'lib/LWP/GSSAPIUserAgent.pm',
    ABSTRACT_FROM       => 'lib/LWP/GSSAPIUserAgent.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'MIME::Base64' => "2.12",
        'GSSAPI' => "0.18",
        'LWP::Debug' => 0,
        'base' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'LWP-GSSAPIUserAgent-*' },
);
