#!/usr/bin/perl
#
#  Copyright (c) 2004, SWITCH - Teleinformatikdienste fuer Lehre und Forschung
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   * Neither the name of SWITCH nor the names of its contributors may be
#     used to endorse or promote products derived from this software without
#     specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#
#  $Author: peter $
#
#  $Id: demoplugin.pm 41 2012-01-15 14:20:42Z peter $
#
#  $LastChangedRevision: 41 $

# Demo plugin for NfSen

# Name of the plugin
package SURFcertAIRTMailer;

use strict;
use NfProfile;
use NfConf;
use Socket;
use Email::Send;
use Email::MIME::Creator;

#
# The plugin may send any messages to syslog
# Do not initialize syslog, as this is done by 
# the main process nfsen-run
use Sys::Syslog;
  
our %cmd_lookup = (
	'try'	=> \&RunProc,
);

# This string identifies the plugin as a version 1.3.0 plugin. 
our $VERSION = 130;

my $EODATA 	= ".\n";

my ( $nfdump, $PROFILEDIR );

#
# Define a nice filter: 
# We like to see flows containing more than 500000 packets
my $nf_filter = 'packets > 500000';

sub RunProc {
	my $socket  = shift;	# scalar
	my $opts	= shift;	# reference to a hash

	# error checking example
	if ( !exists $$opts{'colours'} ) {
		Nfcomm::socket_send_error($socket, "Missing value");
		return;
	}

	# retrieve values passed by frontend
	# two scalars
	my $colour1 = $$opts{'colour1'};
	my $colour2 = $$opts{'colour2'};

	# one array as arrayref
	my $colours = $$opts{'colours'};

	my @othercolours = ( 'red', 'blue' );

	# Prepare answer
	my %args;
	$args{'string'} = "Greetings from backend plugin. Got colour values: '$colour1' and '$colour2'";
	$args{'othercolours'} = \@othercolours;

	Nfcomm::socket_send_ok($socket, \%args);

} # End of RunProc

#
# Periodic data processing function
#	input:	hash reference including the items:
#			'profile'		profile name
#			'profilegroup'	profile group
#			'timeslot' 		time of slot to process: Format yyyymmddHHMM e.g. 200503031200
sub run {
	my $argref 		 = shift;
	my $profile 	 = $$argref{'profile'};
	my $profilegroup = $$argref{'profilegroup'};
	my $timeslot 	 = $$argref{'timeslot'};

	syslog('notice', "demoplugin run: Profilegroup: $profilegroup, Profile: $profile, Time: $timeslot");

	my %profileinfo     = NfProfile::ReadProfile($profile, $profilegroup);
	my $profilepath 	= NfProfile::ProfilePath($profile, $profilegroup);
	my $all_sources		= join ':', keys %{$profileinfo{'channel'}};
	my $netflow_sources = "$PROFILEDIR/$profilepath/$all_sources";

	#syslog('notice', "demoplugin args: '$netflow_sources'");

} # End of run

#
# Alert condition function.
# if defined it will be automatically listed as available plugin, when defining an alert.
# Called after flow filter is applied. Resulting flows stored in $alertflows file
# Should return 0 or 1 if condition is met or not
sub alert_condition {
	my $argref 		 = shift;

	my $alert 	   = $$argref{'alert'};
	my $alertflows = $$argref{'alertfile'};
	my $timeslot   = $$argref{'timeslot'};

	syslog('notice', "Alert condition function called: alert: $alert, alertfile: $alertflows, timeslot: $timeslot");

	# add your code here

	return 1;
}

# Utility subroutine taken from the Internet, to format output bytes appropriately.
sub scale_bytes_output
{
	my( $size, $n ) =( shift, 0 );
	++$n and $size /= 1024 until $size < 1024;
	return sprintf "%.2f %s", $size, ( qw[ bytes K M G ] )[ $n ];
}

# Utility subroutine taken from the Internet, to format output packets appropriately.
sub scale_packets_output
{
	my( $size, $n ) =( shift, 0 );
	++$n and $size /= 1000 until $size < 1000;
	return sprintf "%.2f %s", $size, ( qw[ bytes K M ] )[ $n ];
}

#
# Alert action function.
# if defined it will be automatically listed as available plugin, when defining an alert.
# Called when the trigger of an alert fires.
# Return value ignored
sub alert_action {
	my $argref 	 = shift;

	my $alert    = $$argref{'alert'};
	my $timeslot   = $$argref{'timeslot'};

	# Create the first part of the mail body.
	my $mail_body_string = $NfConf::MAIL_BODY;

	# substitute all vars
	my %replace = ( 
		'alert'		=> 	$alert, 
		'timeslot'	=>	$timeslot,
	);
	
	foreach my $key ( keys %replace ) {
		$mail_body_string =~ s/\@$key\@/$replace{$key}/g;
	}

        # Find out who the top target is.
        my @output;
        my $file = "$NfConf::PROFILEDATADIR/~$alert/$alert/nfcapd.$timeslot";
        if ( open NFDUMP, "$NfConf::PREFIX/nfdump -r $file -q -o csv -n 1 -s ip/bytes 2>&1|" ) {
                local $SIG{PIPE} = sub { syslog('err', "Pipe broke for nfprofile"); };
                @output = <NFDUMP>;
                close NFDUMP;    # SIGCHLD sets $child_exit
        }

	# Extract the IP-address of the top target.
	my $first_ip = "";
	my $outlen = @output;

	# The output must at least have two lines (the header and the top output).
	if ($outlen >= 2)
	{
		my @nffields = split(',', $output[1]);
		$first_ip = $nffields[4];
	}

	# Attempt to resolve the IP-address.
	my $resolvedname = "";
	if (index($first_ip, ":") != -1)
	{
		# Resolve IPv6 address.
		$resolvedname = gethostbyaddr(inet_aton($first_ip), AF_INET6());
	}
	else
	{
		# Resolve IPv4 address.
		$resolvedname = gethostbyaddr(inet_aton($first_ip), AF_INET());
	}

	# -------------------------------------------------------------------------------------
	# Perform some debugging, writing to a separate file that is not rotated.
	my $filename = '/var/log/gijs_debug_mailplugin.log';
	open(my $fh, '>>', $filename) or syslog('notice', "Failed to open $filename!");
	say $fh "-----Timeslot: $timeslot-----";
	foreach (@output)
	{
		say $fh $_;
	}
	say $fh "-----End-----";
	close $fh;
	# -------------------------------------------------------------------------------------
	
	# Perform another query for the top IP address to see which source ports the traffic comes from.
        my @output_detailed;
        my $file1 = "nfcapd.$timeslot";
	my $profilestr = "$NfConf::PROFILEDATADIR/live/JNR01-Asd001A:JNR01-Asd002A";
        if ( open NFDUMP, "$NfConf::PREFIX/nfdump -M $profilestr -T -r $file1 -q -o csv -n 5 -s srcport/bytes 'host $first_ip' 2>&1|" ) {
                local $SIG{PIPE} = sub { syslog('err', "Pipe broke for nfprofile"); };
                @output_detailed = <NFDUMP>;
                close NFDUMP;    # SIGCHLD sets $child_exit
        }

	# Create the mail body, which consists of a machine parsable part and a part to send to the customer.
	$mail_body_string .= ",$first_ip,$resolvedname\r\n\r\n";

	# Pick only the relevant information from the nfdump output.
	# Output format: ts,te,td,pr,val,fl,flP,ipkt,ipktP,ibyt,ibytP,ipps,ibps,ibpp
	$mail_body_string .= "Source Port\tFlows\t\tPackets\t\tVolume\t\tBps\r\n";
	foreach (@output_detailed)
	{
		# Split the line into fields.
		my @detailed_fields = split(',', $_);
		
		# Check if this row is of significance. Take into account that the significance level (20%) is HARD-CODED below!
		my $bytespercent = $detailed_fields[10];
		my $packetspercent = $detailed_fields[8];
		if (($bytespercent >= 20) || ($packetspercent >= 20))
		{
			# Get useful information from this line.
			my $srcport = $detailed_fields[4];
			my $flows = $detailed_fields[5];
			my $flowspercent = $detailed_fields[6];
			my $packets = scale_packets_output $detailed_fields[7];
			my $bytes = scale_bytes_output $detailed_fields[9];
			my $bps = scale_bytes_output $detailed_fields[12];

			$mail_body_string .= "$srcport\t\t$flows ($flowspercent %)\t$packets ($packetspercent %)\t$bytes ($bytespercent %)\t$bps\r\n";
		}
	}	

	# Create the mail message.
	my $mail = Email::MIME->create(
		header => [
			From => $NfConf::MAIL_FROM,
			To => "gijs.rijnders\@surfnet.nl",
			Subject => "Alert Triggered: $alert Top-IP: $first_ip",
		],
		body => $mail_body_string
	);

	# Send the mail message.
	my $sender = Email::Send->new({mailer => 'SMTP'});
	$sender->mailer_args([Host => $NfConf::SMTP_SERVER]);
	my $mail_result = $sender->send($mail);

	# Is it useful to check the mail send function for errors!

	return 1;
}

#
# The Init function is called when the plugin is loaded. It's purpose is to give the plugin 
# the possibility to initialize itself. The plugin should return 1 for success or 0 for 
# failure. If the plugin fails to initialize, it's disabled and not used. Therefore, if
# you want to temporarily disable your plugin return 0 when Init is called.
#
sub Init {
	syslog("info", "demoplugin: Init");

	# Init some vars
	$nfdump  = "$NfConf::PREFIX/nfdump";
	$PROFILEDIR = "$NfConf::PROFILEDATADIR";

	return 1;
}

#
# The Cleanup function is called, when nfsend terminates. It's purpose is to give the
# plugin the possibility to cleanup itself. It's return value is discard.
sub Cleanup {
	#syslog("notice", "demoplugin Cleanup");
	# not used here
}

1;
