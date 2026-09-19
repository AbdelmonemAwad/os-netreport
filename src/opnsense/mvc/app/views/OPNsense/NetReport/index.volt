{#
 # Copyright (C) 2026 Abdelmonem Awad <eg2@live.com>
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without modification,
 # are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright notice,
 #    this list of conditions and the following disclaimer in the documentation
 #    and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<script>
    $(document).ready(function () {
        /* show a rendered report in a wide dialog; the report is a full HTML page, keep it inside an iframe */
        function showReport(title, b64) {
            const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
            const html = new TextDecoder('utf-8').decode(bytes);
            const frame = $('<iframe style="width:100%;height:70vh;border:0;background:#f3f4f6"></iframe>');
            frame.attr('srcdoc', html);
            BootstrapDialog.show({
                title: title,
                message: frame,
                size: BootstrapDialog.SIZE_WIDE,
                buttons: [{label: "{{ lang._('Close') }}", action: function (dialog) { dialog.close(); }}]
            });
        }

        function showResult(data) {
            const ok = data && (data.status === 'sent' || data.status === 'ok');
            let message = ok ? "{{ lang._('The report was sent.') }}" : "{{ lang._('The report was not sent.') }}";
            if (data && data.status === 'skipped') {
                message = "{{ lang._('Nothing needs attention, so the report was skipped as configured.') }}";
            }
            if (data && data.detail) {
                message += '<br/><br/>' + $('<div/>').text(data.detail).html();
            }
            BootstrapDialog.show({
                type: ok ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_WARNING,
                title: "{{ lang._('Network Report') }}",
                message: message,
                buttons: [{label: "{{ lang._('Close') }}", action: function (dialog) { dialog.close(); }}]
            });
            $('#grid-history').bootgrid('reload');
        }

        /* schedules */
        $("#{{ formGridSchedule['table_id'] }}").UIBootgrid({
            search: '/api/netreport/settings/search_schedule',
            get: '/api/netreport/settings/get_schedule/',
            set: '/api/netreport/settings/set_schedule/',
            add: '/api/netreport/settings/add_schedule/',
            del: '/api/netreport/settings/del_schedule/',
            toggle: '/api/netreport/settings/toggle_schedule/',
            commands: {
                preview: {
                    method: function () {
                        const uuid = $(this).data('row-id');
                        const icon = $(this).find('span');
                        icon.addClass('fa-spinner fa-pulse');
                        ajaxGet('/api/netreport/service/preview/' + uuid, {}, function (data) {
                            icon.removeClass('fa-spinner fa-pulse');
                            if (data && data.html) {
                                showReport("{{ lang._('Preview') }}", data.html);
                            } else {
                                showResult(data);
                            }
                        });
                    },
                    classname: 'fa fa-fw fa-eye',
                    title: "{{ lang._('Preview') }}",
                    sequence: 10
                },
                send: {
                    method: function () {
                        const uuid = $(this).data('row-id');
                        const icon = $(this).find('span');
                        BootstrapDialog.confirm({
                            title: "{{ lang._('Send now') }}",
                            message: "{{ lang._('Send this report to its recipients now?') }}",
                            btnOKLabel: "{{ lang._('Send') }}",
                            callback: function (confirmed) {
                                if (!confirmed) {
                                    return;
                                }
                                icon.addClass('fa-spinner fa-pulse');
                                ajaxCall('/api/netreport/service/send/' + uuid, {}, function (data) {
                                    icon.removeClass('fa-spinner fa-pulse');
                                    showResult(data);
                                });
                            }
                        });
                    },
                    classname: 'fa fa-fw fa-paper-plane',
                    title: "{{ lang._('Send now') }}",
                    sequence: 20
                }
            }
        });

        /* only show the fields that matter for the chosen repeat */
        $('#schedule\\.frequency').change(function () {
            const freq = $(this).val();
            $('#row_schedule\\.weekdays').toggle(freq === 'weekly');
            $('#row_schedule\\.monthday').toggle(freq === 'monthly');
        });

        /* settings */
        const data_get_map = {'frm_general': '/api/netreport/settings/get'};
        mapDataToFormUI(data_get_map).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            $('#netreport\\.general\\.mail_source').change();
        });

        $('#netreport\\.general\\.mail_source').change(function () {
            const custom = $(this).val() === 'custom';
            ['smtp_host', 'smtp_port', 'smtp_security', 'smtp_user', 'smtp_password', 'from_address'].forEach(function (f) {
                $('#row_netreport\\.general\\.' + f).toggle(custom);
            });
        });

        $('#saveAct').click(function () {
            saveFormToEndpoint('/api/netreport/settings/set', 'frm_general', function () {
                $('#saveAct_done').show().delay(2000).fadeOut();
            });
        });

        $('#testMailAct').click(function () {
            const btn = $(this);
            saveFormToEndpoint('/api/netreport/settings/set', 'frm_general', function () {
                btn.find('i').addClass('fa fa-spinner fa-pulse');
                ajaxCall('/api/netreport/service/test_mail', {}, function (data) {
                    btn.find('i').removeClass('fa fa-spinner fa-pulse');
                    const ok = data && data.status === 'sent';
                    BootstrapDialog.show({
                        type: ok ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_WARNING,
                        title: "{{ lang._('Test message') }}",
                        message: (ok ? "{{ lang._('A test message was sent.') }}" : "{{ lang._('The test message could not be sent.') }}") +
                            (data && data.detail ? '<br/><br/>' + $('<div/>').text(data.detail).html() : ''),
                        buttons: [{label: "{{ lang._('Close') }}", action: function (dialog) { dialog.close(); }}]
                    });
                });
            }, true);
        });

        /* history */
        const status_text = {
            'sent': "{{ lang._('Sent') }}",
            'skipped': "{{ lang._('Skipped') }}",
            'failed': "{{ lang._('Failed') }}",
            'alert': "{{ lang._('Alert sent') }}"
        };
        $('a[href="#history"]').on('shown.bs.tab', function () {
            if (!$('#grid-history').hasClass('tabulator') && !$('#grid-history').data('loaded')) {
                $('#grid-history').data('loaded', true).UIBootgrid({
                    search: '/api/netreport/service/history',
                    options: {
                        selection: false,
                        multiSelect: false,
                        formatters: {
                            status: function (column, row) {
                                const cls = row.status === 'failed' ? 'text-danger' : (row.status === 'skipped' ? 'text-muted' : 'text-success');
                                return '<span class="' + cls + '">' + (status_text[row.status] || row.status) + '</span>';
                            },
                            view: function (column, row) {
                                if (!row.archive) {
                                    return '';
                                }
                                return '<button type="button" class="btn btn-xs btn-default command-view" data-file="' + row.archive +
                                    '" title="{{ lang._('Open') }}"><span class="fa fa-fw fa-eye"></span></button>';
                            }
                        }
                    }
                }).on('loaded.rs.jquery.bootgrid', function () {
                    $('.command-view').off('click').on('click', function () {
                        ajaxGet('/api/netreport/service/view/' + $(this).data('file'), {}, function (data) {
                            if (data && data.html) {
                                showReport("{{ lang._('Sent report') }}", data.html);
                            }
                        });
                    });
                });
            } else {
                $('#grid-history').bootgrid('reload');
            }
        });

        /* keep the selected tab in the url */
        const selected_tab = window.location.hash !== '' ? window.location.hash : '#schedules';
        $('a[href="' + selected_tab + '"]').tab('show');
        $('.nav-tabs a').on('shown.bs.tab', function (e) {
            history.pushState(null, null, e.target.hash);
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li><a data-toggle="tab" href="#schedules">{{ lang._('Schedules') }}</a></li>
    <li><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#history">{{ lang._('History') }}</a></li>
</ul>

<div class="tab-content content-box">
    <div id="schedules" class="tab-pane fade in">
        <div class="alert alert-info" role="alert" style="margin: 10px;">
            <i class="fa fa-fw fa-info-circle"></i>
            {{ lang._('Each schedule sends one report. Use the eye button to preview it and the plane button to send it now.') }}
        </div>
        {{ partial('layout_partials/base_bootgrid_table', formGridSchedule + {'command_width': '160'}) }}
    </div>
    <div id="settings" class="tab-pane fade in">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
        <div class="col-md-12" style="padding: 10px 15px 20px;">
            <button class="btn btn-primary" id="saveAct" type="button"><b>{{ lang._('Save') }}</b></button>
            <button class="btn btn-default" id="testMailAct" type="button">
                {{ lang._('Save and send test message') }} <i></i>
            </button>
            <span id="saveAct_done" class="text-success" style="display: none; margin: 0 10px;">
                <i class="fa fa-check"></i> {{ lang._('Saved') }}
            </span>
        </div>
    </div>
    <div id="history" class="tab-pane fade in">
        <table id="grid-history" class="table table-condensed table-hover table-striped table-responsive">
            <thead>
                <tr>
                    <th data-column-id="time" data-type="string" data-width="11em">{{ lang._('Time') }}</th>
                    <th data-column-id="schedule" data-type="string">{{ lang._('Report') }}</th>
                    <th data-column-id="subject" data-type="string">{{ lang._('Subject') }}</th>
                    <th data-column-id="recipients" data-type="string">{{ lang._('Recipients') }}</th>
                    <th data-column-id="status" data-formatter="status" data-width="7em">{{ lang._('Status') }}</th>
                    <th data-column-id="detail" data-type="string">{{ lang._('Details') }}</th>
                    <th data-column-id="archive" data-formatter="view" data-sortable="false" data-width="5em"></th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </div>
</div>

{{ partial("layout_partials/base_dialog", ['fields': scheduleForm, 'id': formGridSchedule['edit_dialog_id'], 'label': lang._('Edit report schedule')]) }}
