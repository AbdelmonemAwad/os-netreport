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

namespace OPNsense\NetReport;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

class NetReport extends BaseModel
{
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        $general = $this->general;
        if ($validateFullModel || $general->isFieldChanged()) {
            if ((string)$general->mail_source == 'custom') {
                foreach (['smtp_host', 'smtp_user', 'from_address'] as $field) {
                    if ((string)$general->$field == '') {
                        $messages->appendMessage(new Message(
                            gettext('This field is required when a custom SMTP server is used.'),
                            'general.' . $field
                        ));
                    }
                }
            }
        }

        foreach ($this->schedules->schedule->iterateItems() as $schedule) {
            if (!$validateFullModel && !$schedule->isFieldChanged()) {
                continue;
            }
            if ((string)$schedule->frequency == 'weekly' && (string)$schedule->weekdays == '') {
                $messages->appendMessage(new Message(
                    gettext('Select at least one day for a weekly report.'),
                    $schedule->__reference . '.weekdays'
                ));
            }
        }

        return $messages;
    }
}
