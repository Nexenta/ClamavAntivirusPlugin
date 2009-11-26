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

#FIXME
use Data::Dumper;

##############################  variables  ####################################

my $verb_runner = 'clamav-scan';
my $CLAMAV_RUNNER_TYPE = 'clamav-scan';

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
		'reset' => \&setup_clamav_antivirus_vscan,
		_recompute => \&NMC::Builtins::Show::show_fs_unknown_and_syspool,
		# TODO: need a design, [?folder?] disable/enbable/show [?folder?]
		#show => \&bi_show,
	},
);

my %runner_action =
(
	_help => ["#lastword# the #secondword#"],
	_enter => \&NMC::Builtins::Setup::runner_action_all,
	_usage => \&NMC::Builtins::Setup::runner_action_all_usage,
);

my %runner_words =
(
	_help => ["Show #lastword#s"],
	_enter => \&NMC::Builtins::Show::show_all_runners,
	$NMC::all => {
		_enter => \&NMC::Builtins::Show::show_all_runners,
		_usage => \&NMC::Builtins::Show::show_all_runners_usage,
	},
	_unknown => {
		_help => ["#secondword#: show summary and details"],
		_enter => \&NMC::Builtins::Show::show_runner,
		_usage => \&NMC::Builtins::Show::show_runner_usage,
		_recompute => \&NMC::Builtins::Show::show_runner_unknown, 
	},
);

my %clam_runner_words =
(
	_help => ["Enable, disable, and run appliance #lastword#s"],
	show => \&bi_show,

	disable    => \%runner_action,
	enable     => \%runner_action,
	$NMC::run_now  => \%runner_action,
	# 'reset'     => \%runner_reset_action,

	_unknown => {
		_help => ["Enable, disable, and run #secondword# '#lastword#'"],
		show => \&bi_show,
		_recompute => \&NMC::Builtins::Show::show_runner_unknown, 
		disable    => \%runner_action,
		enable     => \%runner_action,
		$NMC::run_now  => \%runner_action,

		# $NMC::PROPERTY => \%runner_property,

		destroy => {
			_enter => \&clam_runner_destroy,
			# _usage => \&clam_runner_destroy_usage,
		},
		# evaluate => {
			# _enter => \&clam_runner_evaluate,
			# _usage => \&clam_runner_evaluate_usage,
		# },
	},

	create => { 
		_enter => \&clam_runner_create,
		$NMC::FOLDER => {
			_unknown => {
				_enter => \&clam_runner_create,
				_recompute => \&NMC::Builtins::Show::show_fs_unknown_and_syspool,
			},
		},
		# _usage => \&clam_runner_create_usage,
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
				'reset' => \&setup_clamav_antivirus_vscan,
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

	$show_words->{$verb_runner} = \%runner_words;
	$setup_words->{$verb_runner} = \%clam_runner_words;

	$NMC::RESERVED{$verb} = 1;
}

############################## Setup Command ####################################

sub bi_show {
	&NMC::Util::setup_bi_show(@_);
}


sub __check_cicap
{
	my ($verbose, $quiet, $testfile) = @_;
	my $lines;

	eval {
		$lines = &NZA::plugin('nms-clamav-antivirus')->icap( $verbose, $testfile );
	}; if ( nms_catch( $@ ) ) {
		nms_print_error( $@ ) unless $quiet;
		__show_message_reinstall();
		return 1;
	}

	&NMC::Util::nmc_show_less( $lines ) unless $quiet;
	print_out( "C-ICAP: service check OK.\n" ) if $quiet;
	return 0;
}

sub __install_engine
{
	return &NZA::plugin('nms-clamav-antivirus')->install_engine();
}

sub __check_engine
{
	return &NZA::plugin('nms-clamav-antivirus')->check_engine();
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

	my $retval;
	my %fmri = (
		"vscan" => "svc:/system/filesystem/vscan:icap",
		"cicap" => "svc:/application/cicap:default",
		"clamfresh" => "svc:/application/clamfresh:default",
	);

	print_out( "\n=== AntiVirus services status ===\n" );

	foreach my $service ( keys %fmri ) {
		eval {
			$retval = &NZA::smf->get_state( $fmri{$service} );
		}; if ( nms_catch( $@ ) ) {
			nms_print_error( $@ );
		}
		print_out( "$service: $retval\n" );
	}

	__check_cicap( $verbose, $quiet, $testfile ) if defined $check;

	if ( defined $verbose ) {
		print_out( "\n=== Last update log information ===\n" );
		show_clamav_antivirus_update();
		print_out( "\n=== Show Folder/Volumes vscan status on/off ===\n" );
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

   -v	show verbose information about update status, vscan
	engine and configuration
   -c	check if antivirus can detect test virus
   -t	provide test virus file to check, default is
	/usr/share/clamav-testfiles/clam.zip if it exists
   -q	after checking testfile, shows quiet information about the
	successful check
   -a	shows all volumes and folders with "on" and "off" vscan
	status 

Examples:

To show information about last antivirus database update:
${prompt}show clamav-antivirus update

Received signal: wake up
ClamAV update process started at Tue Oct 27 17:00:14 2009
main.cvd is up to date (version: 51, sigs: 540, f-level: 42, builder: sven)
daily.cld is up to date (version: 99, sigs: 930, f-level: 43, builder: ccordes)


To show currently settings of vscan engine, freshclam and c-icap
${prompt}show clamav-antivirus show-settings

max-size=10MB
max-size-action=allow
types=+*

avscan:enable=on
avscan:host=localhost
avscan:port=1344
avscan:max-connection=32

srv_clamav.MaxObjectSize 10M
srv_clamav.ClamAvMaxFilesInArchive 0
srv_clamav.ClamAvMaxFileSizeInArchive 100M
srv_clamav.ClamAvMaxRecLevel 5
Checks 24
DatabaseMirror db.local.clamav.net
DatabaseMirror database.clamav.net


To check the volumes and folders with "on access" vscan engine enabled/disabled:
${prompt}show clamav-antivirus vscan -a

tank/share on
tank/home on
tank/video off
tank/music off


To check if c-icap can detect the infected files and all services are online
${prompt}show clamav-antivirus -c -q

STATE STIME FMRI
online Oct_22 svc:/application/clamfresh:default
online Oct_22 svc:/application/cicap:default
online Oct_22 svc:/application/clamd:default
online Oct_22 svc:/system/filesystem/vscan:icap
C-ICAP: service check OK.

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
}

sub show_clamav_antivirus_vscan
{
	my ($h, @path) = @_;

	my( $all ) = &NMC::Util::get_optional('a', \@path);
	my( $folder, $volume ) = __zfs_set_vscan_get_args( \@path );

	my $list;
	eval {
		$list = &NZA::plugin('nms-clamav-antivirus')->get_vscan_props($volume, $folder, (defined $all) ? '' : 'on');
	}; if (nms_catch($@)) {
		nms_print_error($@);
		return 1;
	}

	my $l = length("NAME");
	foreach my $zname ( keys %$list ) {

		$l = length( $zname ) if ( length( $zname ) > $l );
	}
	$l += 2;
	my $fmt = "%-${l}s%-8s\n";

	hdr_printf( $fmt, "NAME", "VSCAN" ) if scalar keys %$list;

	foreach my $zname ( sort keys %$list ) {

		my $status = $list->{$zname};
		print_out( sprintf( $fmt, $zname, $status ) );
	}

	# &NMC::Util::nmc_show_less( $nza_folders_vscan );
}

sub show_clamav_antivirus_vscan_usage
{
	my ($cmdline, $prompt, @path) = @_;

	print_out <<EOF;
$cmdline
Usage: [-a]

    -a		shows "on" and "off" vscan status information (by default "on")

EOF
}


sub show_clamav_antivirus_config
{
	my ($h, @path) = @_;
	my ($section) = &NMC::Util::names_to_values_from_path( \@path, "section"); 

	my $params;

	eval {
		$params = &NZA::plugin('nms-clamav-antivirus')->get_params($section);
	}; if ( nms_catch( $@ ) ) {
		nms_print_error( $@ );
		return 1;
	}

	foreach my $prop (sort keys %$params) {

		print_out("  $prop = $params->{$prop}\n");
	}

	return 0;
}

sub setup_clamav_antivirus_usage
{
	my ($cmdline, $prompt, @path) = @_;

	print_out <<EOF;
$cmdline
The vscan engine provides "on access" files checking, sets the file attribute
to "q" (quarantine), so users won't be able to get access to the file. 
The file could only be deleted. If the file need to
be copied, you must disable vscan engine in folder which contains the file and
reset the quarantine attribute.

You can also scan Folder "manually". Please note that recursively scan
disabled by default (enable with "-r" option). 
to enable the possibility to remove infected files which were found during 
the virus scanning use "-d" option.
to move these files to the other folder use "-q <DIR>". 

Examples:

Enable "on access" Virus Scanning of the File Systems:
${prompt}setup clamav-antivirus vscan folder tank/games enable

or disable:
${prompt}setup clamav-antivirus vscan volume tank folder trash disable

If you enable vscan in a volume, then all the contained folders inherit this set
${prompt}setup clamav-antivirus vscan volume tank enable

To scan any Folder for viruses manually:
${prompt}setup clamav-antivirus scan folder tank/incoming

----------- SCAN SUMMARY -----------
Known viruses: 637439
Engine version: 0.95.2
Scanned directories: 1
Scanned files: 0
Infected files: 0
Data scanned: 0.00 MB
Data read: 0.00 MB (ratio 0.00:1)
Time: 6.969 sec (0 m 6 s)


To scan Folder recursively and remove infected files:
${prompt}setup clamav-antivirus scan folder tank/incoming -r -d

To check for newest antivirus databases in Internet manually:
${prompt}setup clamav-antivirus update

ClamAV update process started at Tue Oct 27 17:00:14 2009
main.cvd is up to date (version: 51, sigs: 540, f-level: 42, builder: sven)
daily.cld is up to date (version: 99, sigs: 930, f-level: 43, builder: ccordes)


By default antivirus databases update proceed automatically,
you can change it by editing config file of "freshclam"
${prompt}setup clamav-antivirus edit-settings freshclam


EOF
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
	# TODO: yes for immediately apply changes?
	# my ($yes, $value) = NMC::Util::get_optional('ys:', \@path);
	my ($value) = NMC::Util::get_optional('s:', \@path);

	my %setparams = ();

	unless (defined($value)) {
		return 1 if (!NMC::Util::input_field('Value',
				7,
				"Please enter value for property '$property'",
				\$value,
				cmdopt => 's:',
				# current => $prop_val,
				# match => '^\d+[GMK]{1}B$',
				# 'no-ucfirst' => undef,
				# 'on-equal' => $NMC::warn_no_changes,
				'on-empty' => $NMC::warn_no_changes));
		return 1 if (&choose_ret_ctrl_c());
	}

	$setparams{'name'} = $property;
	$setparams{'value'} = $value;

	eval {
		&NZA::plugin('nms-clamav-antivirus')->set_params(\%setparams);
	}; if ( nms_catch( $@ ) ) {
		nms_print_error( $@ );
		return 1;
	}

	return 0;
}

sub setup_clamav_antivirus_property_unknown
{
	my ($h, @path) = @_;
	my ($section) = &NMC::Util::names_to_values_from_path( \@path, "section"); 
	my $props;

	eval {
		$props = &NZA::plugin('nms-clamav-antivirus')->get_params_desc($section);
	}; if ( nms_catch( $@ ) ) {
		nms_print_error( $@ );
		return 1;
	}

	if (scalar keys %$props) {
		for my $k (keys %$props) {
			$h->{$k} = NMC::Util::duplicate_hash_deep($h->{_unknown});
			$h->{$k}{_help} = $props->{$k};
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
		eval {
			&NZA::plugin('nms-clamav-antivirus')->set_vscan_value($vol, $folder, $action);
		}; if ( nms_catch( $@ ) ) {
			nms_print_error( $@ );
			return 1;
		}
	} else {
		push @_, "-a" unless defined $all;
		show_clamav_antivirus_vscan( @_ );
	}
	#return &NMC::Builtins::Show::show_fs_df( @_ );
}


sub setup_clamav_antivirus_update
{
	my ($h, @path) = @_;
	my $lines;
	eval {
		$lines = &NZA::plugin('nms-clamav-antivirus')->freshclam();
	}; if( nms_catch( $@ ) ) {
		nms_print_error( $@ );
		return 1;
	}

	&NMC::Util::nmc_show_less( $lines );
}

#TODO: support location|path not only folders 
sub setup_clamav_antivirus_scan
{
	my ($h, @path) = @_;
	my( $recursive, $delete, $quarantine ) = &NMC::Util::get_optional('rdq:', \@path);
	my ($folder, $vol) = __zfs_set_vscan_get_args(\@path);
	my $lines;

	if ( defined( $folder ) && defined( $vol ) ) {

		eval {
			$lines = &NZA::plugin('nms-clamav-antivirus')->clamscan(
				$vol,
				$folder,
				defined( $recursive ),
				defined( $delete ),
				defined( $quarantine )
				);
		}; if( nms_catch( $@ ) ) {
			nms_print_error( $@ );
			return 1;
		}

		&NMC::Util::nmc_show_less( $lines );

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

   -r 		scans subdirectories recursively (by default "off")
   -d 		removes infected files. Be careful!
   -q <DIR>	moves infected files into DIR

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

In this file please edit parameters beginning with ^srv_clamav.*


EOF
}

sub __clam_runner_create
{
	my ($h, @path) = @_;

	eval {
		&NZA::plugin('nms-clamav-antivirus')->test_internal();
	}; if (nms_catch($@)) {
		nms_print_error($@);
		return 1;
	}

	# NMC::Builtins::Show::show_runner($h, $CLAMAV_RUNNER_TYPE, '-v'); #drop error ((((
}

sub clam_runner_create
{
	my ($h, @path) = @_;
	# my( $recursive, $delete, $quarantine ) = &NMC::Util::get_optional('rdq:', \@path);
	&Data::Dumper::Dumpp([@path]);
	my ($folder, $vol) = __zfs_set_vscan_get_args(\@path);
	my ($pathname, $type, $period, $day_within_period, $time_within_day) =
		NMC::Util::get_optional('n:i:p:D:T:', \@path);
	if ( defined( $folder ) && defined( $vol ) ) {
		my $zname = "$vol/$folder";
		$pathname = &NZA::folder->get_child_prop($zname, 'mountpoint');
	}

	my $field_size = 10;

	return 0 if (!NMC::Util::input_field(
			'path',
			$field_size,
			"A fully qualified path of a custom directory to scan (examples: 'tank/users/mike', '/var/tmp/'). The directory must exist at this point.",
			\$pathname,
			cmdopt => 'n:'));


	if (&NZA::runner->object_exists($pathname)) {
		print_error("$CLAMAV_RUNNER_TYPE '$pathname' object already exists\n");
		return 0;
	}

	if (! -d $pathname) {
		print_error("The directory '$pathname' does not exist.\n");
		return 0;
	}
	
	# schedule in units
	$type = NMC::Builtins::Setup::input_field_ival_type( $type, $field_size, $CLAMAV_RUNNER_TYPE, $NZA::hourly, 'i:');
	return 0 unless ( defined $type );
		
	# 
	# period
	# 
	my ( $units, $default_period ) = NMC::Builtins::Setup::ivaltype_to_units_period( $type );
       	return 0 if (!NMC::Builtins::Setup::input_field_period($type, "period", $field_size,
					 "Period of time$units between automatic '$CLAMAV_RUNNER_TYPE' runs",
					 \$period,
					 $default_period,
					 'p:'));
	
	my ($day, $hour, $minute) = NMC::Builtins::Setup::input_field_day_time($CLAMAV_RUNNER_TYPE,
							 $type,
							 $day_within_period,
							 $time_within_day,
							 $field_size,
							 'D:', 'T:');
	return 0 unless (defined $day);

	# do create
	my ($params, $tunables) = ({}, {});
	$params->{type} = $CLAMAV_RUNNER_TYPE;
	$params->{flags} = 0;   		# TODO: add capability to define flags via UI
	$params->{description} = "create clamav-scan test"; # FIXME: = $params->{info}
	$params->{trace_level} = $NZA::TRACE_LEVEL;
	$params->{freq_type} = $type;
	$params->{freq_period} = $period;
	$params->{freq_minute} = $minute;
	$params->{freq_hour} = $hour;
	$params->{freq_day} = $day;

	eval {
		&NZA::plugin('nms-clamav-antivirus')->schedule_create($pathname, $params, $tunables);
	}; if (nms_catch($@)) {
		nms_print_error($@);
		return 1;
	}

	NMC::Builtins::Show::show_runner($h, $CLAMAV_RUNNER_TYPE, $pathname, '-v');
}

sub clam_runner_destroy
{
	my ($h, @path) = @_;
	my ($yes) = NMC::Util::get_optional('y', \@path);
	my ($name) = NMC::Util::names_to_values_from_path(\@path, $CLAMAV_RUNNER_TYPE);

	if (! $yes) {
		return unless (&NMC::Util::input_confirm("Destroy $CLAMAV_RUNNER_TYPE '$name'?"));
	}
	eval {
		&NZA::plugin('nms-clamav-antivirus')->schedule_destroy($name);
	}; if (nms_catch($@)) {
		nms_print_error($@);
		return 1;
	}
	print_out("$CLAMAV_RUNNER_TYPE '$name' destroyed\n");
}

1;
# vim:set sts=0 ts=8 sw=8 noet:
