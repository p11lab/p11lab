# SPDX-License-Identifier: Apache-2.0
# Trusted Linux amd64 setup. Only this outer process needs CAP_SYS_CHROOT.
use strict;
use warnings;
my ($root, $bytes, $inodes, @command) = @ARGV;
die "missing bounded-rootfs command\n" unless @command;
my $statfs = "\0" x 120;
syscall(137, $root, $statfs) == 0 or die "statfs failed: $!\n";
my @fs = unpack('q15', $statfs);
die "rootfs quota/type mismatch\n" unless $fs[0] == 0x01021994 && $fs[1] * $fs[2] == $bytes && $fs[5] == $inodes;
chroot($root) or die "chroot failed: $!\n";
chdir('/') or die "chdir failed: $!\n";
my $header = pack('LL', 0x20080522, 0);
my $caps = "\0" x 24;
syscall(126, $header, $caps) == 0 or die "capset failed: $!\n";
# Exec a trusted inner gate: NNP must prevent root capability regain at exec.
my $gate = q{
 use strict; use warnings;
 my $header = pack('LL', 0x20080522, 0);
 my $caps = "\0" x 24;
 syscall(125, $header, $caps) == 0 or die "capget failed\n";
 die "payload retained capabilities\n" unless $caps eq "\0" x 24;
 die "no-new-privileges absent\n" unless syscall(157,39,0,0,0,0) == 1;
 die "payload retained chroot authority\n" if chroot('/');
 die "unexpected chroot refusal\n" unless $! == 1;
 $| = 1;
 print "P11LAB_BOUNDED_ROOTFS_CAPS_ZERO_NNP_ONE\n";
 exec {$ARGV[0]} @ARGV;
 die "payload exec failed: $!\n";
};
exec('/usr/bin/perl', '-e', $gate, @command);
die "trusted gate exec failed: $!\n";
