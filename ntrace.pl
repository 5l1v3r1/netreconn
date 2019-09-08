#!/usr/bin/perl -w

use strict;

# Signals we are interested in dealing with:
$SIG{'INT' } = 'intrpt';
$SIG{'HUP' } = 'intrpt';
$SIG{'ABRT'} = 'intrpt';
$SIG{'QUIT'} = 'intrpt';
$SIG{'TRAP'} = 'intrpt';
$SIG{'STOP'} = 'intrpt';

my $NSTROBE_DEFAULT_OPTS = "-x -v -c";
my $EXEC = "/usr/local/bin";
my $NSTROBE_DATA = "/var/tmp/ntrace_strobe.$$";
my $NTRAF_DATA = "/var/tmp/ntrace_ntraf.$$";
my $NDECODE_DATA = "/var/tmp/ntrace_ndecode.$$";
my $NDECODE_FLAG = 0;
my $INTERFACE;
my $SAVELOG = 0;
my $PING = 0;

sub intrpt {
    my($sig) = @_;

    die $sig;
    die;
}

sub usage {
 print "$0 [[option][arguments]]\n";
 print "$0 [-u][-a][-p n-N][-t n.n][-h ip-address or hostname]\n";
 print "Options\n";
 print " -u       Print usage message and exit\n"; # need to intercept
 print " -F       Do full decode\n"; # invoke ndecode as well
 print " -i dev   Specify interface to use\n";     # for ntraf
 print " -P       Ping only check\n";
 print " -p n[-N] Scan port number n or a range of n-N\n"; # for nstrobe
 print " -S       Save trace log\n";
 print " -t n[.n] Set the default scan timeout to SECONDS.USECONDS\n"; # ditto
 print " -h host  Target specification as host or ip address\n";
}

sub exec_strobe {
	my ($optargs) = @_;
	if ($PING == 1) {
		system("$EXEC/nstrobe $NSTROBE_DEFAULT_OPTS -P $optargs > $NSTROBE_DATA");
	} else {
		system("$EXEC/nstrobe $NSTROBE_DEFAULT_OPTS $optargs > $NSTROBE_DATA");
	}
}

sub exec_pcap_op {
	my ($cmd, $outfile, $filter) = @_;
        my $opts;

        if ($INTERFACE) {
            $opts = "-i $INTERFACE";
        } else {
            $opts = "";
        }

	$|=1;

	system("$EXEC/$cmd $opts $filter > $outfile &");
		
	my $pid = `ps -e|grep $cmd|grep -v grep|awk '{print \$1}'`;

	return $pid;
}

sub concat {
	my ($file) = shift;

	open(FILE, $file) || die "Cannot open $file";
	my @contents = <FILE>;
	close FILE;

	print "@contents\n";
}

# main
my $timeout = "3.0";
my $portrange = "2-1024";
my $addrinfo;

while ( my $i = shift @ARGV ) {
    if ($i eq '-u') {
        usage();
        exit (0);
    } elsif ($i eq '-F') {
		$NDECODE_FLAG=1;
    } elsif ($i eq '-i') {
        $INTERFACE = shift @ARGV;
    } elsif ($i eq '-P') {
		$PING = 1;
    } elsif ($i eq '-p') {
        $portrange = shift @ARGV; 
    } elsif ($i eq '-t') {
        $timeout = shift @ARGV;
	} elsif ($i eq '-h') {
		$addrinfo = shift @ARGV;
	} elsif ($i eq '-S') {
		$SAVELOG=1;
    }
}

if (! $addrinfo) {
	print "Syntax error - no target specified\n";
	usage();
	exit (1);
}

my $ntraf_pid;
my $ndecode_pid;
my ($tmp_address, $subnet_end) = split ("-",$addrinfo);
print "Starting Scan and Trace; this may take awhile ...\n";
if ($subnet_end) {
	my @network_address = split ("\\.",$tmp_address);
	$ntraf_pid = exec_pcap_op("ntraf", $NTRAF_DATA, "net $network_address[0].$network_address[1].$network_address[2]");
	if ($NDECODE_FLAG == 1) {
		$ndecode_pid = exec_pcap_op("ndecode",$NDECODE_DATA,  "net $network_address[0].$network_address[1].$network_address[2]");
	}

	exec_strobe("-t $timeout -p $portrange $addrinfo");
} else {
	$ntraf_pid = exec_pcap_op("ntraf", $NTRAF_DATA, "host $addrinfo");
	if ($NDECODE_FLAG == 1) {
		$ndecode_pid =  exec_pcap_op("ndecode",$NDECODE_DATA,"host $addrinfo");
	}

	exec_strobe("-t $timeout -p $portrange $addrinfo");
}

system("sudo kill -9 $ntraf_pid");
system("sudo kill -9 $ndecode_pid");

print "Network Trace Data";  concat($NTRAF_DATA);
print "Network Decode Data"; concat($NDECODE_DATA);
print "Network Scan Data";   concat($NSTROBE_DATA);

if ($SAVELOG) {
	print "Tracefiles saved to $NSTROBE_DATA $NTRAF_DATA";
	if ($NDECODE_FLAG) {
		print " $NDECODE_DATA";
	}
	
	print "\n";
} else {
	unlink ($NSTROBE_DATA);
	unlink ($NTRAF_DATA);
	if ($NDECODE_FLAG == 1) {
		unlink ($NDECODE_DATA);
	}
}

exit 0;
