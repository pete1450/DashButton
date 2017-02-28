use Net::Pcap;
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::TCP;
use Socket;
use LWP::Simple;
use strict;
use File::Basename;

my $err;
my $lastPacketTime = time;
my $currentTime = time;
my %devices;

#load devices from ini
my ( $scriptName, $scriptPath, $scriptSuffix ) = fileparse( $0, qr{\.[^.]*$} );
my $propFile = "$scriptPath$scriptName.ini";
open INI, "<$propFile";
while (my $row = <INI>) {
	chomp $row;
	my @devSplit = split(/\t/, $row);
	$devices{$devSplit[0]} = $devSplit[1];
}

#   Use network device passed in program arguments or if no 
#   argument is passed, determine an appropriate network 
#   device for packet sniffing using the 
#   Net::Pcap::lookupdev method

my $dev = $ARGV[0];
unless (defined $dev) {
    $dev = Net::Pcap::lookupdev(\$err);
    if (defined $err) {
        die 'Unable to determine network device for monitoring - ', $err;
    }
}

#   Look up network address information about network 
#   device using Net::Pcap::lookupnet - This also acts as a 
#   check on bogus network device arguments that may be 
#   passed to the program as an argument
my ($address, $netmask);
if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
    die 'Unable to look up device information for ', $dev, ' - ', $err;
}

my $net = inet_ntoa(  pack 'N', $address  );
my $mask = inet_ntoa(  pack 'N', $netmask);

#print "$net\n";
#print "$mask\n";

#   Create packet capture object on device
my $object;
$object = Net::Pcap::open_live($dev, 1500, 0, 0, \$err);
unless (defined $object) {
    die 'Unable to create packet capture on device ', $dev, ' - ', $err;
}

#   Compile and set packet filter for packet capture 
#   object - For the capture of TCP packets with the SYN 
#   header flag set directed at the external interface of 
#   the local host, the packet filter of '(dst IP) && (tcp
#   [13] & 2 != 0)' is used where IP is the IP address of 
#   the external interface of the machine.  For 
#   illustrative purposes, the IP address of 127.0.0.1 is 
#   used in this example.
my $filter;
Net::Pcap::compile(
    $object, 
    \$filter, 
    '(ip src 0.0.0.0) && (src port 68)', 
    0, 
    $netmask
) && die 'Unable to compile packet capture filter';
Net::Pcap::setfilter($object, $filter) &&
    die 'Unable to set packet capture filter';

#   Set callback function and initiate packet capture loop
Net::Pcap::loop($object, -1, \&syn_packets, '') ||
    die 'Unable to perform packet capture';
Net::Pcap::close($object);

sub syn_packets {
    my ($user_data, $header, $packet) = @_;

    #   Strip ethernet encapsulation of captured packet 

    my $ether_data = NetPacket::Ethernet::strip($packet);

    #   Decode contents of TCP/IP packet contained within 
    #   captured ethernet packet

    my $ip = NetPacket::IP->decode($ether_data);
    my $frame = NetPacket::Ethernet->decode($packet);
    my $tcp = NetPacket::TCP->decode($ip->{'data'});

    #   Print all out where its coming from and where its 
    #   going to!
    #print
    #    $ip->{'src_ip'}, ":", $frame ->{'src_mac'}, ":", $tcp->{'src_port'}, " -> ",
    #    $ip->{'dest_ip'}, ":", $frame ->{'dest_mac'}, ":", $tcp->{'dest_port'}, "\n";
		
	my $srcMac = $frame->{'src_mac'};
	dashPacket($srcMac);
}

sub dashPacket{
	my $currMac = shift;
	$currentTime = time;
	if($currentTime-$lastPacketTime>1 &&  exists $devices{$currMac}){
		my $url = $devices{$currMac};
		get $url;
	}
	$lastPacketTime = time;
}