#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (C) 2006-2009 Nexenta Systems, Inc.
# All rights reserved.
#

package nmc_clamav_antivirus;

use NZA::Common;
use NMC::Const;
use NMC::Util;
use NMC::Term::Clui;
use strict;
use warnings;

use Data::Dumper;

##############################  variables  ####################################

my $verb	= 'clamav-antivirus';
my $prop_name	= 'vscan';

my $engine_name = 'avscan';

my $cmd_avadm	= 'vscanadm';
my $cmd_avfresh	= 'freshclam';
my $cmd_avscan	= 'clamscan';

my $cfg_avfresh = '/etc/clamav/freshclam.conf';
my $cfg_avcicap = '/etc/c-icap.conf';

my $log_avfresh = "/var/log/clamav/freshclam.log"; # XXX: grep UpdateLogFile $cfg_avfresh

my %show_clamav_folder_words = (
	_unknown => {
		_enter => \&show_clamav_antivirus_vscan,
		_usage => \&show_clamav_antivirus_vscan_usage,
		_recompute => \&NMC::Builtins::Show::show_fs_unknown_and_syspool,
	},
);

my %show_clamav_words =
(
	_help => ["Show information about AntiVirus"],
	_enter => \&show_clamav_antivirus,
	_usage => \&show_clamav_antivirus_usage,
	update => \&show_clamav_antivirus_update,
	vscan => {
		_enter => \&show_clamav_antivirus_vscan,
		_usage => \&show_clamav_antivirus_vscan_usage,
		$NMC::FOLDER => \%show_clamav_folder_words,
		$NMC::VOLUME => {
			#_shortcut => \&NMC::Util::volume_shortcut,
			_unknown => {
				_enter => \&show_clamav_antivirus_vscan,
				_usage => \&show_clamav_antivirus_vscan_usage,
				_recompute => \&NMC::Builtins::Show::show_volume_and_syspool_unknown,
				$NMC::FOLDER => \%show_clamav_folder_words,
			},
		},
	},
	'show-settings' => \&show_clamav_antivirus_config,
);

my %setup_clamav_folder_words = (
	_help => ["Select the folder for vscan scan on/off"],
	_unknown => {
		_enter => \&setup_clamav_antivirus_vscan,
		enable => \&setup_clamav_antivirus_vscan,
		disable => \&setup_clamav_antivirus_vscan,
		_recompute => \&NMC::Builtins::Show::show_fs_unknown_and_syspool,
		# TODO: need a design, [?folder?] disable/enbable/show [?folder?]
		#show => \&bi_show,
	},
);

my %setup_clamav_words =
(
	#_enter => {},

	show => \&bi_show,
	_help => ["Setup AntiVirus"],
	_usage => \&setup_clamav_antivirus_usage,
	'edit-settings' => {
		show => \&bi_show,
		_help => ["Configure parameters"],

		freshclam => {
			_enter => \&setup_clamav_antivirus_config_freshclam,
			_usage => \&setup_clamav_antivirus_config_freshclam_usage,
			_help => ["Edit #prevword# configuration file"],
		},
		'c-icap' => {
			_enter => \&setup_clamav_antivirus_config_cicap,
			_usage => \&setup_clamav_antivirus_config_cicap_usage,
			_help => ["Edit #prevword# configuration file"],
		},
	},
	# example "setup appliance nms property"
	$NMC::PROPERTY => {
		show => \&show_clamav_antivirus_config,
		_unknown => {
			_enter => \&setup_clamav_antivirus_property,
			_recompute => \&setup_clamav_antivirus_property_unknown,
		},
	},
	vscan => {
		show => \&bi_show,
		_help => ["Activate on access scan by fs"],
		$NMC::FOLDER => \%setup_clamav_folder_words,
		$NMC::VOLUME => {
			_help => ["Select the volume for vscan on/off"],
			_unknown => {
				_enter => \&setup_clamav_antivirus_vscan,
				enable => \&setup_clamav_antivirus_vscan,
				disable => \&setup_clamav_antivirus_vscan,
				_recompute => \&NMC::Builtins::Show::show_volume_and_syspool_unknown,
				$NMC::FOLDER => \%setup_clamav_folder_words,
			},
		},
	},
	update => {
		show => \&bi_show,
		_help => ["Manual update the virus database"],
		_enter => \&setup_clamav_antivirus_update,
	},
	scan => {
		_help => ["Manual scan ..."],
		$NMC::FOLDER => {
			_help => ["Select the folder for clamscan folder"],
			_usage => \&setup_clamav_antivirus_scan_usage,
			_unknown => {
				_enter => \&setup_clamav_antivirus_scan,
				_recompute => \&NMC::Builtins::Show::show_fs_unknown_and_syspool,
			},
		},
	},
);

my $_clamav_interrupted;


############################## Plugin Hooks ####################################

sub construct {
	my $all_builtin_word_trees = shift;

	my $show_words = $all_builtin_word_trees->{show};
	my $setup_words = $all_builtin_word_trees->{setup};

	$show_words->{$verb} = \%show_clamav_words;
	$setup_words->{$verb} = \%setup_clamav_words;

	$NMC::RESERVED{$verb} = 1;
}

############################## Setup Command ####################################

sub bi_show {
	&NMC::Util::setup_bi_show(@_);
}


sub __check_cicap
{
	my ($verbose, $quiet, $testfile) = @_;
	my @lines = ();
	$testfile = "/usr/share/clamav-testfiles/clam.zip" unless defined $testfile;

	if ( defined $verbose ) {

		if ( ! -f $testfile ) {
			print_error( "Error: icap-client check test virus.\nfile: $testfile not found.\n" );
			return 1;
		}

		if ( sysexec("icap-client -f $testfile -s avscan", \@lines ) != 0 ) {
			print_error( "Error: icap-client check test virus.\n" );
			&NMC::Util::print_execute_lines( \@lines );
			__show_message_reinstall();
			return 1;
		}

	} else {

		if ( sysexec("icap-client", \@lines ) != 0 ) {
			print_error( "Error: icap-client test service reply.\n" );
			&NMC::Util::print_execute_lines( \@lines );
			__show_message_reinstall();
			return 1;
		}
	}

	if ( defined $quiet ) {
		print_out( "C-ICAP: service check OK.\n" );
	} else {
		print_out( "\n=== Checking c-icap service ===\n" );
		&NMC::Util::print_execute_lines( \@lines );
	}
	return 0;
}

sub __install_engine
{
	my @lines = ();

	# TODO: migrate to server part, need replace any specific commands
	print_out( "Try to install $prop_name.\n" );
	my $manifest = '/var/svc/manifest/system/filesystem/vscan.xml';
	my $host = 'localhost';

	# FIXME: check if engine not exists and service exists, etc
	if ( sysexec( "svccfg import $manifest", \@lines ) != 0) {
		print_error("Error: import manifest $prop_name\n");
		&NMC::Util::print_execute_lines( \@lines );
		return 1;
	}

	if ( sysexec( "svcadm enable $prop_name", \@lines ) != 0) {
		print_error("Error: enable service $prop_name\n");
		&NMC::Util::print_execute_lines( \@lines );
		return 1;
	}

	if ( sysexec( "$cmd_avadm add-engine $engine_name", \@lines ) != 0) {
		print_error("Error: add-engine $engine_name\n");
		&NMC::Util::print_execute_lines( \@lines );
		return 1;
	}

	if ( sysexec( "$cmd_avadm set-engine -p host=$host $engine_name", \@lines ) != 0) {
		print_error("Error: set-engine $engine_name\n");
		&NMC::Util::print_execute_lines( \@lines );
		return 1;
	}

	return 0;
}

sub __check_engine
{
	my @lines = ();

	if ( sysexec( "$cmd_avadm get-engine $engine_name", \@lines ) != 0) {
		print_error("Error: engine $engine_name is off\n");
		&NMC::Util::print_execute_lines( \@lines );
		return 1;
	}

	return 0;
}

sub __show_message_reinstall
{
	print_error( "Please try to reinstall this plugin\n" ); # TODO: add get information about current plugin
}

sub __zfs_set_vscan_get_args
{
	my $path = shift;

	my ($vol, $folder) =
	&NMC::Util::names_to_values_from_path($path, 
		$NMC::VOLUME, 
		$NMC::FOLDER); 
	if (! defined $folder) {
		($vol) =
		&NMC::Util::names_to_values_from_path($path,
			$NMC::VOLUME);
	}

	return ( $folder, $vol ); 
}

sub show_clamav_antivirus
{
	my ($h, @path) = @_;
	my ($verbose, $check, $quiet, $testfile, $all) = NMC::Util::get_optional('vcqt:a', \@path);

	my @lines = ();

	# &NZA::smf->get_names( '' );
	# only returns:
	# 'svc:/application/nmv:default'
	# 'svc:/network/apache2:default'
	# 'svc:/network/ftp:default'
	# 'svc:/network/iscsi_initiator:default'
	# 'svc:/network/ldap/client:default'
	# 'svc:/network/nfs/client:default'
	# 'svc:/network/nfs/server:default'
	# 'svc:/network/ntp:default'
	# 'svc:/network/rsync:default'
	# 'svc:/network/smb/server:default'
	# 'svc:/network/snmpd:default'
	# 'svc:/network/ssh:default'
	# 'svc:/system/hal:default'
	# 'svc:/system/iscsitgt:default'
	# 'svc:/system/ndmpd:default'
	# or &NZA::Utils::clear_enable_smf_svc
	# NZA::Utils::set_smf_confopt
	# NZA::Utils::get_smf_confopt
	# NZA::Utils::del_smf_confgroup

	# my %fmri = (
	# "vscan" => "svc:/system/filesystem/vscan:icap",
	# "cicap" => "svc:/application/cicap:default",
	# "clamd" => "svc:/application/clamd:default",
	# "clamfresh" => "svc:/system/filesystem/vscan:icap",
	# );
	#Plugin::NmcClamAV
	#&NZA::smf->set_child_prop( $fmri{'vscan'}, 'vscan', 'on' );
	#$retval = &NZA::smf->get_state( $fmri{'vscan'} );
	#print_out( "vscan: $retval\n" );
	# TODO: migrate to server part, add services to &NZA::smf
	if ( sysexec("svcs {vscan,cicap,clamd,clamfresh}", \@lines) == 0 ) {
		print_out( "\n=== AntiVirus services status ===\n" );
		&NMC::Util::print_execute_lines( \@lines );
	} else {
		print_error( "Error: check services depends.\n" );
		&NMC::Util::print_execute_lines( \@lines );
		__show_message_reinstall();
		return 1;
	}

	__check_cicap( ( $verbose, $quiet, $testfile ) ) if defined $check;

	if ( defined $verbose ) {
		print_out( "\n=== Last update log information ===\n" );
		show_clamav_antivirus_update();
		print_out( "\n=== Show Folder/Volumes vscan status ===\n" );
		push @_, "-a" if defined $all;
		show_clamav_antivirus_vscan( @_ );
		print_out( "\n=== Show AntiVirus configuration ===\n" );
		show_clamav_antivirus_config();
	}

}

sub show_clamav_antivirus_usage
{
	my ($cmdline, $prompt, @path) = @_;

	print_out <<EOF;
$cmdline
Usage: [-v] [-c] [-t testfile] [-q] [-a]

    -v 			show verbose information about update, vscan and config
    -c 			check if antivirus can detect test virus
    -t <testfile>	provide test virus file to check, default is
    			/usr/share/clamav-testfiles/clam.zip if it exists
    -q 			when checked testfile, quiet information about the
    			successful check
    -a			show all volumes and folders with "on" and "off" vscan
    			status 

"on access" set the file attribute to -q- quarantine and users wouldn't be able
to get access to the file. this file cold be only deleted. if the file need to
be copied, you must disable vscan engine in folder which contains the file and
drop the quarantine atribute.

"by hand" scan selected Folder, recursively disabled by default,
enable the posibility to remove infected file or move to destionation Folder. 

Example:

To check the volumes and folders with "on access" vscan engine enabled/disabled:
${prompt}setup clamav-antivirus vscan show -a

Enable "on access" Virus Scanning on the File Systems:
${prompt}setup clamav-antivirus vscan folder tank/games enable

or disable:
${prompt}setup clamav-antivirus vscan volume tank folder trash disable

You can enbale vscan in a volume and all folders it contains inherit this set
${prompt}setup clamav-antivirus vscan volume tank enable

Scan any Folder for viruses manually
${prompt}setup clamav-antivirus scan folder tank/incoming

Scan Folder recursively and remove all

Check for newest antivirus databases in Internet manually
${prompt}setup clamav-antivirus update

By default antivirus databases automaticaly downloaded from the Internet,
you can change it by editing config file of "freshclam"
${prompt}setup clamav-antivirus edit-settings freshclam

To check if c-icap can detect the infected files
${prompt}setup clamav-antivirus show -c

EOF
}

sub show_clamav_antivirus_update
{
	my ($h, @path) = @_;

	#print_out( "\n=== Last antivirus database update ===\n" );

	my ($log_lines_count, $log_lines);

	eval {
		#&NMC::Util::nmc_show_any_file( $logfile, 'NMC::Util::nmc_show_less' );
		my $log_viewer = &NZA::logviewer();
		$log_lines_count = $log_viewer->get_linecount( $log_avfresh ); #get_tail
		$log_lines = $log_viewer->get_lines( $log_avfresh, $log_lines_count, 0 );
		if ( ! $log_lines_count ) {
			print_error( "Error: size of freshclam log is null\n" );
			&NMC::Util::print_execute_lines( $log_lines );
			return 1;
		}
		my $log_content = join( "", @$log_lines );
		my @log_per_run = split( /^[-]+$/m, $log_content ); #split by -----
		my @log_normal = ();
		foreach ( @log_per_run ) {
			s/^\s+//; #ltrim
			s/\s+$//; #rtrim
			push (@log_normal, $_ ) if /\w+/;
		}
		print_out( pop( @log_normal )."\n" ) if $#log_normal; #scalar(@log_normal);

	}; if (nms_catch($@)) {
		print_error( "Error: get freshclam log file\n" );
		nms_print_error($@);
		return 1;
	}

	#my $cmd = q(ruby1.8 -e "puts File.read('/var/log/clamav/freshclam.log').split(/^[-]+$/).select{|s|s=~/\w+/}.pop.strip");
	#my @lines = ();
	#if ( nmc_is_server() ) {
	#if ( sysexec( $cmd, \@lines ) != 0 ) {
	#print_error( "Error: can't exec ruby\n" );
	#return 1;
	#}
	#&NMC::Util::print_execute_lines( \@lines );
	#} else {
	#&NMC::Util::print_warning( "Error: not server \n" );
	#system( $cmd );
	#}
}

sub show_clamav_antivirus_vscan
{
	my ($h, @path) = @_;

	my( $all ) = &NMC::Util::get_optional('a', \@path);
	my( $folder, $volume ) = __zfs_set_vscan_get_args( \@path );

	#FIXME _less
	#no folders found with vscan on, try param -a, and see all folders and
	#volumes where u can set vscan
	#print_out( "\n=== Current active vscan ===\n" );

	my $nza_folders_vscan = ();
	my $zfs_path =	( ( defined $volume ) ? $volume : '' ) .
	( ( defined $folder ) ? '/' . $folder : '' );

	eval {
		if ( defined( $all ) ) {
			# NOTE: scalar @$nza_folders_vscan return 1 if count 1
			# $#$nza_folders_vscan return 0 if 1, -1 if 0, 3 if 4
			$nza_folders_vscan = &NZA::folder->get_all_names( $zfs_path );
		} else {
			# XXX: where is volume?
			$nza_folders_vscan = &NZA::folder->get_names_by_prop( 'vscan', 'on', $zfs_path );
		}
	}; if ( nms_catch( $@ ) ) {
		nms_print_error( $@ );
		return 1;
	}

	my $l = 4; # NAME
	foreach my $folder_name ( @$nza_folders_vscan ) {

		$l = length( $folder_name ) if ( length( $folder_name ) > $l );
	}
	$l += 2;
	my $fmt = "%-${l}s%-8s\n";

	hdr_printf( $fmt, "NAME", "VSCAN" ) if scalar @$nza_folders_vscan;

	#&NMC::Util::print_list( @$nza_folders_vscan );
	#FIXME: replace folder_name variable name to zfs_name or zfs_path
	foreach my $folder_name ( sort @$nza_folders_vscan ) {

		#TODO if $folder_name is only $volume_name, return off
		my $status;

		if ( $folder_name =~ m/^([\w\.\-]+)\/([\w\.\-]+)/ ) {
			eval {
				$status = &NZA::folder->get_child_prop( $folder_name, "vscan" );
			}; if ( nms_catch( $@ ) ) {
				nms_print_error( $@ );
				return 1;
			}
		} else {
			my @lines = ();
			# TODO: migrate to server part, $NZA::folder-get_child_prop(...
			if ( sysexec("zfs get -Hp -o value $prop_name $folder_name", \@lines) != 0 ) {
				print_error("Error: get property $prop_name for $folder_name failed\n");
				$status = 'unknown';
			} else {
				$status = join('', @lines);
			}
		}

		print_out( sprintf( $fmt, $folder_name, $status ) );
	}
}

sub show_clamav_antivirus_vscan_usage
{
	my ($cmdline, $prompt, @path) = @_;

	print_out <<EOF;
$cmdline
Usage: [-a]

    -a		show "on" and "off" vscan status information

EOF
}


sub show_clamav_antivirus_config
{
	my ($h, @path) = @_;

	my @lines = ();

	if ( ! -f $cfg_avcicap ) {
		print_error( "Error: not found $cfg_avcicap.\n" );
		__show_message_reinstall();
		return 1;
	}
	if ( ! -f $cfg_avfresh ) {
		print_error( "Error: not found $cfg_avfresh.\n" );
		__show_message_reinstall();
		return 1;
	}

	# TODO: need a design, show clamav-antivirus config engine/freshclam/c-icap
	if ( sysexec( "$cmd_avadm show", \@lines ) != 0 ) {
		print_error( "Error: execute $cmd_avadm show.\n" );
		&NMC::Util::print_execute_lines( \@lines );
		__show_message_reinstall();
		return 1;
	}

	# &NMC::Util::nmc_show_any_file($cfg_avcicap, 'NMC::Util::nmc_show_less');
	if ( sysexec( qq#egrep "(^srv_clamav.ClamAvMaxFilesInArchive|^srv_clamav.ClamAvMaxFileSizeInArchive|^srv_clamav.ClamAvMaxRecLevel|^srv_clamav.MaxObjectSize)" $cfg_avcicap#, \@lines ) != 0 ) {
		print_error( "Error: execute grep ... $cfg_avcicap.\n" );
		&NMC::Util::print_execute_lines( \@lines );
		__show_message_reinstall();
		return 1;
	}

	# &NMC::Util::nmc_show_any_file($cfg_avfresh, 'NMC::Util::nmc_show_less');
	if ( sysexec( qq#egrep "(^Checks|^DatabaseMirror)" $cfg_avfresh#, \@lines ) != 0 ) {
		print_error( "Error: execute grep ... $cfg_avfresh.\n" );
		&NMC::Util::print_execute_lines( \@lines );
		__show_message_reinstall();
		return 1;
	}

	&NMC::Util::print_execute_lines( \@lines );
}

sub setup_clamav_antivirus_property_show
{
	my ($h, @path) = @_;
	my( $verbose ) = &NMC::Util::get_optional('v', \@path);

	push @_, "-v" unless defined $verbose;

	return bi_show( @_ );
}

sub setup_clamav_antivirus_property
{
	my ($h, @path) = @_;
	my ($property) = &NMC::Util::names_to_values_from_path( \@path, $NMC::PROPERTY); 

	my $new_val;
	my $prop_val;
	my @lines = ();

	if ( defined ( $property ) ) {

		if ( $property eq 'maxfilesize' ) {

			if ( sysexec("$cmd_avadm get -p max-size", \@lines ) != 0 ) {
				print_error( "Error: get $NMC::PROPERTY $property.\n" );
				&NMC::Util::print_execute_lines( \@lines );
				__show_message_reinstall();
				return 1;
			}

			$prop_val = join('', @lines );
			# $prop_val =~ s/^\s+//;
			# $prop_val =~ s/\s+$//;
			$prop_val =~ s/max-size=(\d+[GMK]{1}B)/$1/;
			$prop_val = "10MB" unless ( $prop_val =~ m/\d+[GMK]{1}B/ );

			return 0 if ( ! &NMC::Util::input_field($prop_name,
					0,
					"Enter value of max file size",
					\$new_val,
					current => $prop_val,
					#cmdopt => 's:',
					cmdopt => '',
					match => '^\d+[GMK]{1}B$',
					'no-ucfirst' => undef,
					"on-empty" => $NMC::warn_no_changes,
					"on-equal" => $NMC::warn_no_changes));

			if ( sysexec( "$cmd_avadm set -p max-size=$new_val", \@lines ) != 0 ) {
				print_error( "Error: set $NMC::PROPERTY $property to value $new_val.\n" );
				&NMC::Util::print_execute_lines( \@lines );
				#__show_message_reinstall();
				return 1;
			}

			# XXX: setting will change after 1-3min.
			# show_clamav_antivirus_config(@_);

			return 0;
		}

		print_error( "Error: property $property not exists.\n" );

	} else {

		print_error( "Error: unknown property.\n" );
	}
	return 1;
}

sub setup_clamav_antivirus_property_unknown
{
	my ($h, @path) = @_;
	my $props;

	# skip redundant tree re-calculations
	#return $h if (exists $h->{'smtp_server'});
	my %prop_desc = (
		maxfilesize		=> ["Maximum file size"],
		# maxfilesizeinarchive 	=> ["Maximum file size stored in archives"],
		# maxfilesinarchive 	=> ["Maximum count files in arhives"],
		# maxrecursionlevel 	=> ["Maximum count of sub arhives"],
		# databasemirror 	=> ["Select the mirror of virus database"],
		# quarantinefolder 	=> ["Manual scan quarantine files stored location"],
	);

	# eval {
	# $props = &NZA::server->list_props();
	# }; if (nms_catch($@)) {
	# nms_print_error($@);
	# return 0;
	# }
	if (scalar keys %prop_desc) {
		for my $k (keys %prop_desc) {
			$h->{$k} = NMC::Util::duplicate_hash_deep($h->{_unknown});
			$h->{$k}{_help} = $prop_desc{$k};
		}
	}

	NMC::Util::save_orig_hash_keys($h);
	return $h;
}

sub setup_clamav_antivirus_vscan
{
	my ($h, @path) = @_;
	my( $all ) = &NMC::Util::get_optional('a', \@path);
	my ($folder, $vol) = __zfs_set_vscan_get_args(\@path);
	#supported action is 'enable', 'disable', 'reset', 'destroy', 'remove'
	#name_suffix /^:/
	my( $action, $name_suffix) = &NMC::Util::names_auto_from_path( @path );

	my @lines = ();

	if ( defined( $action ) ) {
		if ( __check_engine() ) { # true if error
			__install_engine();
			if ( __check_engine() ) { # after install check
				return 1;
			}
		}
		# TODO: add inherit
		#if ( $action eq 'reset' ) {
		#zfs inherit vscan ...
		if ( $action eq 'enable' ) {
			if ( defined( $folder ) && defined( $vol ) ) {
				# TODO: migrate to server part
				#&NZA::folder->set_child_prop( "$vol/$folder", $prop_name, "on" );
				#com.nexenta.nms.PropertyAccessDenied:
				#FolderContainer: denied access to property vscan
				#- allowed: ri, attempted: w
				if ( sysexec( "zfs set $prop_name=on $vol/$folder", \@lines ) != 0 ) {
					print_error("Error: $action $prop_name for folder $vol/$folder\n");
					&NMC::Util::print_execute_lines( \@lines );
					return 1;
				}

			} else {
				if ( defined( $vol ) ) {
					# TODO: migrate to server part
					#&NZA::volume->set_child_prop( "$vol", $prop_name, "on" );
					#com.nexenta.nms.PropertyNotFound:
					#Interface com.nexenta.nms.Volume
					#does not publish property vscan
					if ( sysexec( "zfs set $prop_name=on $vol", \@lines ) != 0 ) {
						print_error("Error: $action $prop_name\n");
						&NMC::Util::print_execute_lines( \@lines );
						return 1;
					}
				}
			}
			# push @_, "-a" unless defined $all;
			# show_clamav_antivirus_vscan( @_ );
			return 0;
		}
		if ( $action eq 'disable' ) {
			if ( defined( $folder ) && defined( $vol ) ) {
				# TODO: migrate to server part
				#&NZA::folder->set_child_prop( "$vol/$folder", $prop_name, "off" );
				if ( sysexec( "zfs set $prop_name=off $vol/$folder", \@lines ) != 0 ) {
					print_error("Error: $action $prop_name for folder $vol/$folder\n");
					&NMC::Util::print_execute_lines( \@lines );
					return 1;
				}

			} else {
				if ( defined( $vol ) ) {
					# TODO: migrate to server part
					#&NZA::volume->set_child_prop( "$vol", $prop_name, "on" );
					if ( sysexec( "zfs set $prop_name=off $vol", \@lines ) != 0 ) {
						print_error("Error: $action $prop_name on volume: $vol\n");
						&NMC::Util::print_execute_lines( \@lines );
						return 1;
					}
				}
			}
			# push @_, "-a" unless defined $all;
			# show_clamav_antivirus_vscan( @_ );
			return 0;
		}

		print_error("Error: unknown action $action\n");
		return 1;

	} else {
		push @_, "-a" unless defined $all;
		show_clamav_antivirus_vscan( @_ );
	}
	#return &NMC::Builtins::Show::show_fs_df( @_ );
}

sub setup_clamav_antivirus_vscan_usage
{
	my ($cmdline, $prompt, @path) = @_;

	print_out <<EOF;
	$cmdline
Usage: 
    setup clamav-antivirus vscan Volume/Folder, enable/disable/reset

    vscan set quarantine flag to file "on access"
EOF
}

# XXX: this is example, not in word tree
# sub setup_clamav_antivirus_vscan_unknown
# {
	# my ($h, @path) = @_;

	# #$h = &NMC::Builtins::Show::show_volume_and_syspool_unknown;
	# #$h = &NMC::Builtins::Show::show_fs_unknown;

	# #NMC::Util::save_orig_hash_keys($h);
	# my $folders = ();
	# my $values = ();

	# eval {
		# $folders = &NZA::folder->get_names('([\w\-\.]+)/([\w\-\.]+)');
	# }; if ($@) {
		# print_error( "Error: get folder names\n" );
		# return 1;
	# }
	# for my $f (@$folders) {
		# $h->{$f} = $h->{_unknown};
	# }

	# eval {
		# $values = &NZA::volume->get_names('');
	# }; if ($@) {
		# print_error( "Error: get volume names\n" );
		# return 1;
	# }
	# for my $vol (@$values) {
		# $h->{$vol} = $h->{_unknown};
	# }

	# return $h;
# }

sub setup_clamav_antivirus_update
{
	my ($h, @path) = @_;
	my @lines = ();

	#TODO: add -v
	#XXX: break with error, why?
	if ( sysexec("freshclam", \@lines) != 0 ) {
		print_error( "Error: execute freshclam.\n" );
		&NMC::Util::print_execute_lines( \@lines );
		return 1;
	}

	return 0;
}

#TODO: support location|path not only folders 
sub setup_clamav_antivirus_scan
{
	my ($h, @path) = @_;
	my( $recursive, $delete, $quarantine ) = &NMC::Util::get_optional('rdq:', \@path);
	my ($folder, $vol) = __zfs_set_vscan_get_args(\@path);
	my @lines = ();

	$cmd_avscan .= " -r" if defined( $recursive );
	$cmd_avscan .= " --remove=yes" if defined( $delete );
	$cmd_avscan .= " --move=$quarantine" if defined( $quarantine );

	if ( defined( $folder ) && defined( $vol ) ) {

		if ( sysexec("$cmd_avscan /volumes/$vol/$folder", \@lines) != 0 ) {
			print_error( "ALERT: in $folder VIRUS found!\n" );
			&NMC::Util::print_execute_lines( \@lines );
			return 1;
		}

		&NMC::Util::print_execute_lines( \@lines );

		return 0;

	} else {
		print_error( "Error: please select the folder.\n" );
		return 1;
	}

}

sub setup_clamav_antivirus_scan_unknown
{
	my ($h, @path) = @_;

	return $h;
}

sub setup_clamav_antivirus_scan_usage
{
	my ($cmdline, $prompt, @path) = @_;

	print_out <<EOF;
	$cmdline

Usage: [-r] [-d] [-q DIR]

   -r		Scan subdirectories recursively (default: off)
   -d		Remove infected files. Be careful!
   -q <DIR>	Move infected files into DIR

EOF
}

sub setup_clamav_antivirus_config_freshclam
{
	my ($h, @path) = @_;

	my $changed = NMC::Util::nmc_edit_any_file( $cfg_avfresh,
		'NMC::Util::nmc_setup_edit');
	return 0 if (! $changed);

	return 1; # TODO: restart service? (see: NMC::Builtins::Setup->generic_config_edit)

}
sub setup_clamav_antivirus_config_freshclam_usage
{
	my ($cmdline, $prompt, @path) = @_;

	print_out <<EOF;
	$cmdline

Edit freshclam configuration file.

Beware: advanced usage only.


EOF
}

sub setup_clamav_antivirus_config_cicap
{
	my ($h, @path) = @_;

	my $changed = NMC::Util::nmc_edit_any_file( $cfg_avcicap,
		'NMC::Util::nmc_setup_edit');
	return 0 if (! $changed);

	return 1; # TODO: restart service? (see: NMC::Builtins::Setup->generic_config_edit)
}

sub setup_clamav_antivirus_config_cicap_usage
{
	my ($cmdline, $prompt, @path) = @_;

	print_out <<EOF;
	$cmdline

Edit c-icap configuration file.

Beware: advanced usage only.

Edit in this file only params begins ^srv_clamav.*


EOF
}

1;
# vim:set sts=0 ts=8 sw=8 noet:
