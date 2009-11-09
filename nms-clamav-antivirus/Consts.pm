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

##########################################################################
package NZA::ClamAVConsts;
########################################################################

$NZA::ClamAV::CMD_VSCANADM = 'vscanadm';
$NZA::ClamAV::CMD_CLAMSCAN = 'clamscan';
$NZA::ClamAV::CMD_FRESHCLAM = 'freshclam';
$NZA::ClamAV::CMD_ICAP_CLIENT = 'icap-client';
$NZA::ClamAV::TEST_FILE = '/usr/share/clamav-testfiles/clam.zip';

$NZA::ClamAV::ENGINE_NAME = 'avscan';
$NZA::ClamAV::ENGINE_HOST = 'localhost';

$NZA::ClamAV::FMRI_VSCAN = 'svc:/system/filesystem/vscan:icap';
$NZA::ClamAV::FMRI_FRESHCLAM = 'svc:/application/clamfresh:default';
$NZA::ClamAV::FMRI_CICAP = 'svc:/application/cicap:default';

$NZA::ClamAV::CONF_FRESHCLAM = '/etc/clamav/freshclam.conf';
$NZA::ClamAV::CONF_CICAP = '/etc/c-icap.conf';

$NZA::ClamAV::CONF_FRESHCLAM_NAME = "freshclam";
%NZA::ClamAV::CONF_FRESHCLAM_PROPS = (
	'Checks' => ["Default: 24", "Check for new database N times a day"], # 'a' or 'per'
	'DatabaseMirror' => ["Default: database.clamav.net", "Select the mirror of virus database"],
);
$NZA::ClamAV::CONF_CICAP_NAME = "cicap";
%NZA::ClamAV::CONF_CICAP_PROPS = (
	'srv_clamav.ClamAvMaxFileSizeInArchive' => ["Default: 0", "Maximum file size stored in archives", "0 - unlimit"],
	'srv_clamav.ClamAvMaxFilesInArchive' => ["Default: 100M", "Maximum count files in arhives", "0 - unlimit"],
	'srv_clamav.ClamAvMaxRecLevel' => ["Default: 5", "Maximum count of sub arhives", "0 - unlimit"],
	'srv_clamav.MaxObjectSize' => ["Default: 10M", "C-ICAP: Maximum file size"],
);
$NZA::ClamAV::CONF_VSCAN_NAME = "vscan";
%NZA::ClamAV::CONF_VSCAN_PROPS = (
	'max-size' => ["Default: 10Mb", "VSCAN: Maximum file size"],
);

%NZA::ClamAV::CONF_ALL_PROPS = (
	$NZA::ClamAV::CONF_FRESHCLAM_NAME => \%NZA::ClamAV::CONF_FRESHCLAM_PROPS,
	$NZA::ClamAV::CONF_CICAP_NAME => \%NZA::ClamAV::CONF_CICAP_PROPS,
	$NZA::ClamAV::CONF_VSCAN_NAME => \%NZA::ClamAV::CONF_VSCAN_PROPS,
);

$NZA::ClamAV::LOG_FRESHCLAM = "/var/log/clamav/freshclam.log";


1;

