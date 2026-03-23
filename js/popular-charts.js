$(function () {

    /* ---------------------------------------------------------- *
     * Helpers
     * ---------------------------------------------------------- */

    function getOS(vendor) {
        if (!vendor) return 'Other';
        var v = vendor.toLowerCase();
        if (/microsoft/.test(v))          return 'Microsoft';
        if (/apple/.test(v))              return 'Apple';
        if (/google|android/.test(v))     return 'Google';
        return 'Other';
    }

    function getType(t) {
        if (!t || t === '???') return 'Unknown';
        return t.trim();
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
     * Main — fetch, parse, render
     * ---------------------------------------------------------- */

    $.ajax({
        url: 'data/cve_data.csv',
        dataType: 'text',
        success: function (csvText) {
            var data = parseCSV(csvText).filter(isValid);

            var os      = { Microsoft: 0, Apple: 0, Google: 0, Other: 0 };
            var types   = {};
            var vendors = {};

            data.forEach(function (row) {
                var o = getOS(row['Vendor']);
                os[o]++;

                var t = getType(row['Type']);
                types[t] = (types[t] || 0) + 1;

                var vnd = row['Vendor'] || 'Unknown';
                vendors[vnd] = (vendors[vnd] || 0) + 1;
            });

            /* ---- bar chart: by vendor ---- */
            var sortedVendors = Object.keys(vendors).sort(function (a, b) {
                return vendors[b] - vendors[a];
            });
            Morris.Bar({
                element: 'morris-bar-chart',
                data: sortedVendors.map(function (v) { return { y: v, count: vendors[v] }; }),
                xkey: 'y',
                ykeys: ['count'],
                labels: ['0-days'],
                barColors: ['#1a7abf'],
                hideHover: 'auto',
                resize: true
            });

            /* ---- donut: OS bucket ---- */
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

            /* ---- donut: vuln type ---- */
            var typeEntries = Object.keys(types).sort(function (a, b) {
                return types[b] - types[a];
            });
            Morris.Donut({
                element: 'morris-os-chart',
                data: typeEntries.map(function (t) { return { label: t, value: types[t] }; }),
                resize: true
            });

            /* ---- top-8 summary table ---- */
            var recent = data.slice().sort(function (a, b) {
                return (b['Date Patched'] || '').localeCompare(a['Date Patched'] || '');
            }).slice(0, 8);

            $('#cve-summary-table tbody').html(
                recent.map(function (row) {
                    return '<tr>' +
                        '<td><a href="' + (row['Advisory'] || '#') + '" target="_blank">' + row['CVE'] + '</a></td>' +
                        '<td>' + (row['Vendor'] || '') + '</td>' +
                        '<td><span class="label label-default">' + getType(row['Type']) + '</span></td>' +
                        '</tr>';
                }).join('')
            );
        },

        error: function () {
            console.warn(
                '[popular-charts.js] Could not load data/cve_data.csv. ' +
                'Serve the dashboard through a local web server.'
            );
        }
    });

});
