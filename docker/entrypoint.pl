#!/usr/bin/env perl

use strict;
use English;
use POSIX;
use File::stat;
use User::grent;
use User::pwent;

my $st = stat "/io" or die "Could not stat /io: $!";
my $uid = $st->uid;
my $gid = $st->gid;
my $home = "/home/builder";
my $user = "builder";

if (!getgrgid($gid)) {
    system (
        "groupadd",
        "--gid",
        $gid,
        $user,
    ) == 0 or die "Could not execute groupadd: $!";
}

if (!getpwuid($uid)) {
    system (
        "useradd",
        "--uid",
        $uid,
        "--gid",
        $gid,
        "--home",
        $home,
        $user,
    ) == 0 or die "Could not execute useradd: $!";
}

my $pw = getpwuid($uid);
$ENV{USER} = $user;
$ENV{HOME} = $home;
$EGID = "$gid $gid";
setgid $gid or die "Could not setgid($gid): $!";
setuid $uid or die "Could not setuid($uid): $!";
exec @ARGV or die "Could not exec ${\(join(' ', @ARGV))}: $!";
