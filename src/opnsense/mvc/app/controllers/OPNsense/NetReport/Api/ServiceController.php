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

namespace OPNsense\NetReport\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    private function run($action, $params = [])
    {
        return (new Backend())->configdpRun('netreport ' . $action, $params, false, 300);
    }

    private function validUuid($uuid)
    {
        return is_string($uuid) && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $uuid);
    }

    /**
     * render a report for the schedule without sending it
     */
    public function previewAction($uuid = null)
    {
        if (!$this->validUuid($uuid)) {
            return ['status' => 'failed', 'detail' => gettext('Save the schedule first.')];
        }
        /* base64: API output is html-escaped, the report is a full page shown in an iframe */
        return ['status' => 'ok', 'html' => base64_encode($this->run('preview', [$uuid]))];
    }

    /**
     * send the report for the schedule right now
     */
    public function sendAction($uuid = null)
    {
        if (!$this->request->isPost() || !$this->validUuid($uuid)) {
            return ['status' => 'failed', 'detail' => gettext('Save the schedule first.')];
        }
        $response = json_decode($this->run('send', [$uuid]), true);
        return is_array($response) ? $response : ['status' => 'failed', 'detail' => gettext('No response from the report script.')];
    }

    /**
     * send a short test message to check the mail settings
     */
    public function testMailAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $response = json_decode($this->run('testmail'), true);
        return is_array($response) ? $response : ['status' => 'failed', 'detail' => gettext('No response from the report script.')];
    }

    public function historyAction()
    {
        $records = json_decode($this->run('history'), true);
        /* the script returns the newest entry first */
        return $this->searchRecordsetBase(is_array($records) ? $records : []);
    }

    /**
     * show an archived copy of a report that was sent
     */
    public function viewAction($name = null)
    {
        if (!is_string($name) || !preg_match('/^[0-9A-Za-z_-]+\.html$/', $name)) {
            return ['status' => 'failed'];
        }
        return ['status' => 'ok', 'html' => base64_encode($this->run('view', [$name]))];
    }
}
