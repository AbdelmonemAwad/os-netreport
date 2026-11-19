#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * config.xml encrypted as System: Configuration: Backups encrypts a download - with the same class,
 * OPNsense\Backup\Local, so that page restores it with the password. The password comes on stdin
 * (netreport.py's weekly backup), the encrypted file goes to stdout. Exit 2: no password, 1: failed.
 */

require_once('script/load_phalcon.php');

/* OPNsense's encrypt writes the password and config.xml beside its output for openssl: readable by
 * root alone while they are there */
umask(0077);

$pass = stream_get_contents(STDIN);
if ($pass === false || $pass === '') {
    fwrite(STDERR, "no backup password\n");
    exit(2);
}
$data = @file_get_contents('/conf/config.xml');
if ($data === false || $data === '') {
    fwrite(STDERR, "config.xml could not be read\n");
    exit(1);
}
$out = (new OPNsense\Backup\Local())->encrypt($data, $pass);
if ($out === null) {
    fwrite(STDERR, "the configuration could not be encrypted\n");
    exit(1);
}
echo $out;
