$(function () {

    /* ---------------------------------------------------------- *
     * Helpers
     * ---------------------------------------------------------- */

    function getOS(vendor) {
        if (!vendor) return 'Other';
        var v = vendor.toLowerCase();
        if (/microsoft/.test(v))       return 'Microsoft';
        if (/apple/.test(v))           return 'Apple';
        if (/google|android/.test(v))  return 'Google';
        return 'Other';
    }

    function getType(t) {
        if (!t || t === '???') return 'Unknown';
        return t.trim().toLowerCase().replace(/(?:^|\s)\S/g, function (c) { return c.toUpperCase(); });
    }

    function cveYear(cveId) {
        var m = /CVE-(\d{4})-/.exec(cveId);
        return m ? m[1] : null;
    }

    function isValid(row) {
        return row['CVE'] && /^CVE-\d{4}-\d+/.test(row['CVE'].trim());
    }

    /* ---------------------------------------------------------- *
     * RFC-4180 CSV parser
     * ---------------------------------------------------------- */

    function parseLine(line) {
        var result = [], cur = '', inQ = false;
        for (var i = 0; i < line.length; i++) {
            var c = line[i];
            if (c === '"') {
                if (inQ && line[i + 1] === '"') { cur += '"'; i++; }
                else inQ = !inQ;
            } else if (c === ',' && !inQ) {
                result.push(cur); cur = '';
            } else {
                cur += c;
            }
        }
        result.push(cur);
        return result;
    }

    function parseCSV(text) {
        var lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
        var headers = parseLine(lines[0]).map(function (h) { return h.replace(/^\uFEFF/, '').trim(); });
        var rows = [];
        for (var i = 1; i < lines.length; i++) {
            var line = lines[i].trim();
            if (!line) continue;
            var vals = parseLine(line);
            var row = {};
            headers.forEach(function (h, idx) { row[h] = (vals[idx] || '').trim(); });
            rows.push(row);
        }
        return rows;
    }

    /* ---------------------------------------------------------- *
     * Main — fetch once, render whatever is on the page
     * ---------------------------------------------------------- */

    $.ajax({
        url: 'data/cve_data.csv',
        dataType: 'text',
        success: function (csvText) {
            var data = parseCSV(csvText).filter(isValid);

            /* ---- aggregate everything upfront ---- */
            var total   = data.length;
            var os      = { Microsoft: 0, Apple: 0, Google: 0, Other: 0 };
            var types   = {};
            var years   = {};
            var vendors = {};

            data.forEach(function (row) {
                os[getOS(row['Vendor'])]++;

                var t = getType(row['Type']);
                types[t] = (types[t] || 0) + 1;

                var y = cveYear(row['CVE']);
                if (y) years[y] = (years[y] || 0) + 1;

                var vnd = row['Vendor'] || 'Unknown';
                vendors[vnd] = (vendors[vnd] || 0) + 1;
            });

            /* ---- stat panels (index.html) ---- */
            if ($('#cve-stat-total').length) {
                $('#cve-stat-total').text(total.toLocaleString());
                var uniqueTypes = new Set(data.map(function (r) { return r['Type']; }).filter(Boolean)).size;
                $('#cve-stat-types').text(uniqueTypes.toLocaleString());
                var uniqueProducts = new Set(data.map(function (r) { return r['Product']; })).size;
                $('#cve-stat-products').text(uniqueProducts.toLocaleString());
                $('#cve-stat-years').text(Object.keys(years).length.toLocaleString());
            }

            /* ---- area chart: 0-days by year (index.html) ---- */
            if ($('#morris-area-chart').length) {
                var sortedYears = Object.keys(years).sort();
                Morris.Area({
                    element: 'morris-area-chart',
                    data: sortedYears.map(function (y) { return { period: y, cves: years[y] }; }),
                    xkey: 'period',
                    ykeys: ['cves'],
                    labels: ['0-days'],
                    pointSize: 3,
                    hideHover: 'auto',
                    resize: true
                });
            }

            /* ---- bar chart: top 15 vendors (popular-charts.html) ---- */
            if ($('#morris-bar-chart').length) {
                var top15 = Object.keys(vendors).sort(function (a, b) {
                    return vendors[b] - vendors[a];
                }).slice(0, 15);
                Morris.Bar({
                    element: 'morris-bar-chart',
                    data: top15.map(function (v) { return { y: v, count: vendors[v] }; }),
                    xkey: 'y',
                    ykeys: ['count'],
                    labels: ['CVEs'],
                    barColors: ['#1a7abf'],
                    hideHover: 'auto',
                    resize: true
                });
            }

            /* ---- donut: OS distribution (popular-charts.html) ---- */
            if ($('#morris-donut-chart').length) {
                Morris.Donut({
                    element: 'morris-donut-chart',
                    data: [
                        { label: 'Microsoft', value: os.Microsoft },
                        { label: 'Apple',     value: os.Apple     },
                        { label: 'Google',    value: os.Google    },
                        { label: 'Other',     value: os.Other     }
                    ],
                    colors: ['#00a8e0', '#555555', '#34a853', '#f0ad4e'],
                    resize: true
                });
            }

            /* ---- donut: vuln type (popular-charts.html) ---- */
            if ($('#morris-os-chart').length) {
                var typeEntries = Object.keys(types).sort(function (a, b) {
                    return types[b] - types[a];
                });
                Morris.Donut({
                    element: 'morris-os-chart',
                    data: typeEntries.map(function (t) { return { label: t, value: types[t] }; }),
                    resize: true
                });
            }

            /* ---- horizontal bar: all vendors (vendor-breakdown.html) ---- */
            if ($('#vendor-chart').length) {
                var allVendors = Object.keys(vendors).sort(function (a, b) {
                    return vendors[b] - vendors[a];
                });
                var counts = allVendors.map(function (v) { return vendors[v]; });
                $('#vendor-chart-container').height(Math.max(300, allVendors.length * 32));
                var ctx = document.getElementById('vendor-chart').getContext('2d');
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: allVendors,
                        datasets: [{
                            label: 'CVEs',
                            data: counts,
                            backgroundColor: '#1a7abf',
                            borderColor: '#145e93',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                callbacks: {
                                    label: function (ctx) {
                                        return ' ' + ctx.parsed.x + ' CVE' + (ctx.parsed.x !== 1 ? 's' : '');
                                    }
                                }
                            }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                title: { display: true, text: 'Number of CVEs' },
                                ticks: { precision: 0 }
                            },
                            y: { ticks: { font: { size: 12 } } }
                        },
                        onHover: function (event, elements) {
                            event.native.target.style.cursor = elements.length ? 'pointer' : 'default';
                        },
                        onClick: function (event, elements) {
                            if (!elements.length) return;
                            var vendor = allVendors[elements[0].index];
                            var rows = data.filter(function (r) {
                                return (r['Vendor'] || 'Unknown') === vendor;
                            });

                            $('#vendor-detail-name').text(
                                vendor + ' — ' + rows.length + ' CVE' + (rows.length !== 1 ? 's' : '')
                            );

                            if ($.fn.DataTable.isDataTable('#vendor-detail-table')) {
                                $('#vendor-detail-table').DataTable().destroy();
                                $('#vendor-detail-table tbody').empty();
                            }

                            $('#vendor-detail-table').DataTable({
                                data: rows.map(function (r) {
                                    return [
                                        '<a href="' + (r['Advisory'] || '#') + '" target="_blank">' + r['CVE'] + '</a>',
                                        r['Product']         || '',
                                        getType(r['Type']),
                                        r['Date Discovered'] || '???',
                                        r['Date Patched']    || '???',
                                        r['Description']     || ''
                                    ];
                                }),
                                columns: [
                                    { title: 'CVE ID' },
                                    { title: 'Product' },
                                    { title: 'Type' },
                                    { title: 'Date Discovered' },
                                    { title: 'Date Patched' },
                                    { title: 'Description' }
                                ],
                                pageLength: 25,
                                order: [[3, 'desc']],
                                columnDefs: [{ orderable: false, targets: [5] }]
                            });

                            $('#vendor-detail-panel').show();
                            $('html, body').animate({
                                scrollTop: $('#vendor-detail-panel').offset().top - 70
                            }, 400);
                        }
                    }
                });
            }

            /* ---- horizontal bar: all exploit types (exploit-type.html) ---- */
            if ($('#exploit-type-chart').length) {
                var allTypes = Object.keys(types).sort(function (a, b) {
                    return types[b] - types[a];
                });
                var typeCounts = allTypes.map(function (t) { return types[t]; });
                $('#exploit-type-chart-container').height(Math.max(300, allTypes.length * 32));
                var typeCtx = document.getElementById('exploit-type-chart').getContext('2d');
                new Chart(typeCtx, {
                    type: 'bar',
                    data: {
                        labels: allTypes,
                        datasets: [{
                            label: 'CVEs',
                            data: typeCounts,
                            backgroundColor: '#5cb85c',
                            borderColor: '#4cae4c',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                callbacks: {
                                    label: function (ctx) {
                                        return ' ' + ctx.parsed.x + ' CVE' + (ctx.parsed.x !== 1 ? 's' : '');
                                    }
                                }
                            }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                title: { display: true, text: 'Number of CVEs' },
                                ticks: { precision: 0 }
                            },
                            y: { ticks: { font: { size: 12 } } }
                        },
                        onHover: function (event, elements) {
                            event.native.target.style.cursor = elements.length ? 'pointer' : 'default';
                        },
                        onClick: function (event, elements) {
                            if (!elements.length) return;
                            var exploitType = allTypes[elements[0].index];
                            var rows = data.filter(function (r) {
                                return getType(r['Type']) === exploitType;
                            });

                            $('#exploit-type-detail-name').text(
                                exploitType + ' — ' + rows.length + ' CVE' + (rows.length !== 1 ? 's' : '')
                            );

                            if ($.fn.DataTable.isDataTable('#exploit-type-detail-table')) {
                                $('#exploit-type-detail-table').DataTable().destroy();
                                $('#exploit-type-detail-table tbody').empty();
                            }

                            $('#exploit-type-detail-table').DataTable({
                                data: rows.map(function (r) {
                                    return [
                                        '<a href="' + (r['Advisory'] || '#') + '" target="_blank">' + r['CVE'] + '</a>',
                                        r['Vendor']          || '',
                                        r['Product']         || '',
                                        r['Date Discovered'] || '???',
                                        r['Date Patched']    || '???',
                                        r['Description']     || ''
                                    ];
                                }),
                                columns: [
                                    { title: 'CVE ID' },
                                    { title: 'Vendor' },
                                    { title: 'Product' },
                                    { title: 'Date Discovered' },
                                    { title: 'Date Patched' },
                                    { title: 'Description' }
                                ],
                                pageLength: 25,
                                order: [[3, 'desc']],
                                columnDefs: [{ orderable: false, targets: [5] }]
                            });

                            $('#exploit-type-detail-panel').show();
                            $('html, body').animate({
                                scrollTop: $('#exploit-type-detail-panel').offset().top - 70
                            }, 400);
                        }
                    }
                });
            }

            /* ---- CVE DataTable (index.html + data.html) ---- */
            if ($('#cve-full-table').length) {
                /* index.html shows 10 rows; data.html shows 50 */
                var pageLen = $('#cve-stat-total').length ? 10 : 50;
                $('#cve-full-table').DataTable({
                    data: data.map(function (row) {
                        return [
                            '<a href="' + (row['Advisory'] || '#') + '" target="_blank">' + row['CVE'] + '</a>',
                            row['Vendor']          || '',
                            row['Product']         || '',
                            getType(row['Type']),
                            row['Date Discovered'] || '???',
                            row['Date Patched']    || '???',
                            row['Description']     || ''
                        ];
                    }),
                    columns: [
                        { title: 'CVE ID' },
                        { title: 'Vendor' },
                        { title: 'Product' },
                        { title: 'Type' },
                        { title: 'Date Discovered' },
                        { title: 'Date Patched' },
                        { title: 'Description' }
                    ],
                    pageLength: pageLen,
                    order: [[5, 'desc']],
                    columnDefs: [{ orderable: false, targets: [6] }]
                });
            }
        },

        error: function () {
            console.warn('[charts.js] Could not load data/cve_data.csv. Serve via a local web server.');
        }
    });

});
