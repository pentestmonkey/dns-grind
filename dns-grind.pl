#!/usr/bin/perl -w
# dns-grind - Performs lots of DNS queries quickly
# Copyright (C) 2006 pentestmonkey@pentestmonkey.net
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as 
# published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  If these terms are not acceptable to 
# you, then do not use this tool.
# 
# You are encouraged to send comments, improvements or suggestions to
# me at dns-grind@pentestmonkey.net
#

use strict;
use Net::DNS;
use Socket;
use IO::Handle;
use IO::Select;
use Getopt::Std;
$| = 1;

my $VERSION        = "1.0";
my $debug          = 0;
my @child_handles  = ();
my $verbose        = 0;
my $max_procs      = 25;
my @prefixes       = ();
my @suffixes       = ();
my $recursive_flag = 1;
my $nameserver     = undef;
my $query_timeout  = 5;
my $start_time     = time();
my $end_time;
my $kill_child_string = "\x00";
$SIG{CHLD} = 'IGNORE'; # auto-reap
my %opts;
my $usage=<<USAGE;
dns-grind v$VERSION ( http://pentestmonkey.net/tools/dns-grind )

Usage: dns-grind.pl [options] -f file query-type
       dns-grind.pl [options] ( -p prefix | -P file ) | ( -s suffix | -S file ) query-type

query-type is one of:
        A
	NS
	MX
	PTR

options are:
        -m n     Maximum number of resolver processes (default: $max_procs)
        -p       Prefix of hostname or domain
	-P file  File of hostname or domain prefixes
	-s       Suffix of hostname or domain
	-S file  File of hostname of domain suffixes
	-f       File of hostnames or domains
	-n host  Nameserver to use (default: determined by OS)
	-d       Debugging output
	-r 0|1   Use recursive queries (default: $recursive_flag)
	-t n     Wait a maximum of n seconds for reply (default: $query_timeout)
	-v       Verbose
	-h       This help message

Also see readme.pdf from the dns-grind tar ball.

Examples:

1) Resolve all hostnames in a file to IP addresses:

dns-grind.pl -f hosts.txt A

2) Find domains with domain prefix foobar (e.g. foobar.ac, foobar.ad, ...)

dns-grind.pl -p foobar -S tlds.txt NS

3) Find hostnames for a list of IP addresses

dns-grind.pl -f ips.txt PTR

USAGE

getopts('m:p:P:s:S:f:hvdn:r:t:', \%opts);

# Print help message if required
if ($opts{'h'}) {
	print $usage;
	exit 0;
}

my $query_type = shift;
my $prefix        = $opts{'p'} if $opts{'p'};
my $prefix_file   = $opts{'P'} if $opts{'P'};
my $suffix        = $opts{'s'} if $opts{'s'};
my $suffix_file   = $opts{'S'} if $opts{'S'};
my $file          = $opts{'f'} if $opts{'f'};

$nameserver     = $opts{'n'} if $opts{'n'};
$max_procs      = $opts{'m'} if $opts{'m'};
$verbose        = $opts{'v'} if $opts{'v'};
$debug          = $opts{'d'} if $opts{'d'};
$recursive_flag = $opts{'r'} if $opts{'r'};

# Check for illegal option combinations
unless ($query_type) {
	print $usage;
	exit 1;
}

if ($recursive_flag != 1 and $recursive_flag != 0) {
	print "ERROR: $recursive_flag is not a valid option for -r.  Must be 0 or 1.  -h for help\n";
	exit 1;
}

if ( defined($file) and (
		defined($prefix) or
		defined($prefix_file) or
		defined($suffix) or
		defined($suffix_file)
	)
) {
	print "ERROR: Illegal option combination.  -f can't be used with suffixes or prefixes.  -h for help.\n";
	exit 1;
}

unless (defined($file) or
	(defined($prefix) or defined($prefix_file)) and (defined($suffix) or defined($suffix_file))
) {
	print "ERROR: Specify a file with -f, or some prefixes and suffixes.  -h for help.\n";
	exit 1;
}

# Check for strange option combinations
if (
	(defined($suffix) and defined($suffix_file))
	or
	(defined($prefix) and defined($prefix_file))
) {
	print "WARNING: You specified a lone prefix or suffix AND a file of them.  Continuing anyway...\n";
}

# Shovel prefixes and suffix into arrays
if (defined($prefix_file)) {
	open(FILE, "<$prefix_file") or die "ERROR: Can't open prefix file $prefix_file: $!\n";
	@prefixes = map { chomp($_); $_ } <FILE>;
}

if (defined($suffix_file)) {
	open(FILE, "<$suffix_file") or die "ERROR: Can't open prefix file $suffix_file: $!\n";
	@suffixes = map { chomp($_); $_ } <FILE>;
}

if (defined($prefix)) {
	push @prefixes, $prefix;
}

if (defined($suffix)) {
	push @suffixes, $suffix;
}

if (defined($suffix_file) and not @suffixes) {
	print "ERROR: Suffix file $suffix_file was empty\n";
	exit 1;
}

if (defined($prefix_file) and not @prefixes) {
	print "ERROR: Suffix file $prefix_file was empty\n";
	exit 1;
}

print "Starting dns-grind v$VERSION ( http://pentestmonkey.net/tools/dns-grind )\n";
print "\n";
print " ----------------------------------------------------------\n";
print "|                   Scan Information                       |\n";
print " ----------------------------------------------------------\n";
print "\n";
print "Resolver Processes ..... $max_procs\n";
print "Records file ........... $file\n" if defined($file);
print "Suffixes file .......... $suffix_file\n" if defined($suffix_file);
print "Prefixes file .......... $prefix_file\n" if defined($prefix_file);
print "Suffix count ........... " . scalar(@suffixes) . "\n" if @suffixes;
print "Prefix count ........... " . scalar(@prefixes) . "\n" if @prefixes;
print "Query timeout .......... $query_timeout secs\n";
print "Recursive queries ...... " . ($recursive_flag ? "On" : "Off") . "\n";
if (defined($nameserver)) {
print "DNS Server ............. $nameserver\n";
} else {
print "DNS Server ............. Determine by OS\n";
}
print "\n";
print "######## Scan started at " . scalar(localtime()) . " #########\n";

# Create DNS resolver object
my $res;
if (defined($nameserver)) {
	$res = Net::DNS::Resolver->new(recurse => $recursive_flag, nameservers => [$nameserver]);
} else {
	$res = Net::DNS::Resolver->new(recurse => $recursive_flag);
}


# Spawn off correct number of children
foreach my $proc_count (1..$max_procs) {
	socketpair(my $child, my $parent, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or  die "socketpair: $!";
	$child->autoflush(1);
	$parent->autoflush(1);

	# Parent executes this
	if (my $pid = fork) {
		close $parent;
		print "[Parent] Spawned child with PID $pid to do resolving\n" if $debug;
		push @child_handles, $child;

	# Chile executes this
	} else {
		close $child;
		while (1) {
			my $timed_out = 0;

			# Read domain from parent
			my $domain = <$parent>;
			next unless defined($domain);
			chomp($domain);

			# Exit if told to by parent
			if ($domain eq $kill_child_string) {
				print "[Child $$] Exiting\n" if $debug;
				exit 0;
			}
			
			# Do query with timeout
			my $query;
			eval {
				local $SIG{ALRM} = sub { die "alarm\n" };
				alarm $query_timeout;
				$query = $res->query($domain, uc($query_type));
				alarm 0;
			};

			if ($@) {
				$timed_out = 1;
				print "[Child $$] Timeout for $domain\n" if $debug;
			}

			my $trace;
			if ($debug) {
				$trace = "[Child $$] $domain\t";
			} else {
				$trace = "$domain\t";
			}

			if ($query and not $timed_out) {
				my @results;

				if (uc($query_type) eq "A") {
					@results = map { $_->address } grep { $_->type eq 'A' } $query->answer;
				}

				if (uc($query_type) eq "NS") {
					@results = map { $_->nsdname } grep { $_->type eq 'NS' } $query->answer;
				}

				if (uc($query_type) eq "PTR") {
					@results = map { $_->ptrdname } grep { $_->type eq 'PTR' } $query->answer;
				}

				if (uc($query_type) eq "MX") {
					@results = map { $_->exchange } grep { $_->type eq 'MX' } $query->answer;
				}

				# print $parent $trace . join(",",  map { $_->nsdname } grep { $_->type eq 'NS' } $query->answer) . "\n";
				print $parent $trace . join(",",  @results) . "\n";
			}

			if ($timed_out) {
				print $parent $trace . "<timeout>\n";
			} else {
				if (!$query) {
					print $parent $trace . "<no result>\n";
				}
			}

			# print "CHILD: Child $$ finished\n";
		}
		exit;
	}
}

# Fork once more to make a process that will feed us domains
socketpair(my $get_next_domain, my $parent, AF_UNIX, SOCK_STREAM, PF_UNSPEC) or  die "socketpair: $!";
$get_next_domain->autoflush(1);
$parent->autoflush(1);

# Parent executes this
if (my $pid = fork) {
	close $parent;

# Chile executes this
} else {
	# Generate domains from prefix-suffix pairs and send to parent
	foreach my $prefix (@prefixes) {
		foreach my $suffix (@suffixes) {
			my $domain = $prefix . "." . $suffix;
			print "[Domain Generator] Sending $domain to parent\n" if $debug;
			print $parent "$domain\n";
		}
	}

	# Read domains from file and send to parent
	if ($file) {
		open (FILE, "<$file") or die "Can't open file $file: $!\n";

		while (<FILE>) {
			my $domain = $_;
			chomp($domain);
			print "[Domain Generator] Sending $domain to parent\n" if $debug;
			print $parent "$domain\n";
		}
	}

	exit 0;
}

# printf "Created %d child processes\n", scalar(@child_handles);
my $s = IO::Select->new();
my $s_in = IO::Select->new();
$s->add(@child_handles);
$s_in->add(\*STDIN);
my $timeout = 0; # non-blocking
my $more_domains = 1;
my $outstanding_queries = 0;
my $query_count = 0;
my $result_count = 0;

# Write to each child process once
writeloop: foreach my $write_handle (@child_handles) {
	my $domain = <$get_next_domain>;
	if ($domain) {
		chomp($domain);
		print "[Parent] Sending $domain to child\n" if $debug;
		print $write_handle "$domain\n";
		$outstanding_queries++;
	} else {
		print "[Parent] Quitting main loop.  All domains have been read.\n" if $debug;
		last writeloop;
	}
}

# Keep reading from child processes until there is nothing
# write to a child only after it has been read from
mainloop: while (1) {
	# Wait until there's a child that we can either read from or written to.
	my ($rh_aref) = IO::Select->select($s, undef, undef); # blocking

	print "[Parent] There are " . scalar(@$rh_aref) . " children that can be read from\n" if $debug;

	foreach my $read_handle (@$rh_aref) {
		# Read from child
		chomp(my $line = <$read_handle>);
		if ($verbose == 1 or $debug == 1 or not ($line =~ /no result/ or $line =~ /<timeout>/)) {
			print "$line\n";
			$result_count++ unless ($line =~ /no result/ or $line =~ /<timeout>/);
		}
		$outstanding_queries--;
		$query_count++;

		# Write to child
		my $domain = <$get_next_domain>;
		if ($domain) {
			chomp($domain);
			print "[Parent] Sending $domain to child\n" if $debug;
			print $read_handle "$domain\n";
			$outstanding_queries++;
		} else {
			print "DEBUG: Quitting main loop.  All domains have been read.\n" if $debug;
			last mainloop;
		}
	}
}

# Wait to get replies back from remaining children
my $count = 0;
readloop: while ($outstanding_queries) {
	my @ready_to_read = $s->can_read(1); # blocking
	foreach my $child_handle (@ready_to_read) {
		print "[Parent] Outstanding queries: $outstanding_queries\n" if $debug;
		chomp(my $line = <$child_handle>);
		if ($verbose == 1 or $debug == 1 or not ($line =~ /no result/ or $line =~ /<timeout>/)) {
			print "$line\n";
			$result_count++ unless ($line =~ /no result/ or $line =~ /<timeout>/);
		}
		print $child_handle "$kill_child_string\n";
		$s->remove($child_handle);
		$outstanding_queries--;
		$query_count++;
	}
}

# Tell any remaining children to exit
foreach my $handle ($s->handles) {
	print "[Parent] Telling child to exit\n" if $debug;
	print $handle "$kill_child_string\n";
}

# Wait for all children to terminate
while(wait != -1) {};

print "######## Scan completed at " . scalar(localtime()) . " #########\n";
print "$result_count results.\n";
print "\n";
$end_time = time(); # Second granularity only to avoid depending on hires time module
my $run_time = $end_time - $start_time;
$run_time = 1 if $run_time < 1; # Avoid divide by zero
printf "%d queries in %d seconds (%0.1f queries / sec)\n", $query_count, $run_time, $query_count / $run_time;
