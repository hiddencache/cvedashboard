$(function () {

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
            if (/^CVE-\d{4}-\d+/.test(row['CVE'])) rows.push(row);
        }
        return rows;
    }

    $.ajax({
        url: 'data/cve_data.csv',
        dataType: 'text',
        success: function (csvText) {
            var data = parseCSV(csvText);
            $('#cve-full-table').DataTable({
                data: data.map(function (row) {
                    return [
                        '<a href="' + (row['Advisory'] || '#') + '" target="_blank">' + row['CVE'] + '</a>',
                        row['Vendor']          || '',
                        row['Product']         || '',
                        row['Type']            || '',
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
                pageLength: 50,
                order: [[5, 'desc']],
                columnDefs: [{ orderable: false, targets: [6] }]
            });
        },
        error: function () {
            console.warn('[data-table.js] Could not load data/cve_data.csv.');
        }
    });

});
