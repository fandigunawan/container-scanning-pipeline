$(document).ready(function () {
    var btnList = $('#btn-list');
    var banner = $('#banner');

    $.getJSON('http://localhost:8000/get_all_whitelists', function (data) {
        btnList.empty();
        var i;
        for( i = 0; i < data.length; i++ ) {

            const d = new Object();
            d.filepath = data[i][0];
            d.filename = d.filepath.substr(d.filepath.lastIndexOf('/') + 1);
            d.image_version = d.filename.substring(0, d.filename.lastIndexOf("-whitelist"));
            d.image = d.image_version.split(":")[0];
            d.version = d.image_version.split(":")[1];
            d.buttonid = i;
            d.branch = data[i][1];

            var but = $('<button/>', {
                text: d.filename,
                id: 'btn_'+i,
                click: function() {
                    clearAll();

                    var report_s3;
                    $.getJSON('http://localhost:8000/get?name=' + d.image + '&ver=' + d.version, function (data) {
                        var parent_name = data['parent_name']
                        var parent_version = data['parent_version']

                        report_s3 = data['report_s3']
                         $.getJSON('http://localhost:8000/last_runs?url=' + report_s3, function (run_data) {
                            $('#runs').empty();
                            var q;
                            var links = [];
                            for ( q = 0; q < run_data.length; q++ ) {
                                var header = run_data[q].header;
                                var link = run_data[q].link
                                links[q] = run_data[q].link

                                var s3_return_total;
                                $('#runs').append($("<tr>").html("<a href=# id="+link+">" + header + "</a>" ).click( function(event)  {
                                    clearJenkinsDetailsTable();
                                    $.getJSON('http://localhost:8000/compare?url=' + event.target.id, function (s3_return_data) {

                                        s3_return_total = s3_return_data.total;
//                                        console.log("s3_return_total: ", s3_return_total)
                                        var a;
                                        for( a=0; a < s3_return_data.total.length; a++ ){
                                            var item = s3_return_data.total[a];
                                            $('#total').append($("<tr>").html(convertVulnURLtoHTML(item)));
                                        }
                                        for( a=0; a < s3_return_data.oscap.length; a++ ){
                                            var item = s3_return_data.oscap[a];
                                            $('#oscap').append($("<tr>").html(convertVulnURLtoHTML(item)));
                                        }
                                        for( a=0; a < s3_return_data.oval.length; a++ ) {
                                            var item = s3_return_data.oval[a];
                                            $('#oval').append($("<tr>").html(convertVulnURLtoHTML(item)));
                                        }
                                        for( a=0; a < s3_return_data.twistlock.length; a++ ) {
                                            var item = s3_return_data.twistlock[a];
                                            $('#twistlock').append($("<tr>").html(convertVulnURLtoHTML(item)));
                                        }
                                        for( a=0; a < s3_return_data.anchore.length; a++ ) {
                                            var item = s3_return_data.anchore[a];
                                            $('#anchore').append($("<tr>").html(convertVulnURLtoHTML(item)));
                                        }

                                        $('#delta-list').empty();
                                        $('#delta-count').empty();
                                        var set_delta = getTotalDelta(s3_return_total, data.complete_whitelist)
                                        //$('#delta-list').append($("<tr>").html(convertVulnURLtoHTML(item)));
//                                        $('#delta-list').append($("<tr>").html(set_delta));
                                        $('#delta-count').text(set_delta.size);
                                        $('#delta-list').text(Array.from(set_delta).join(', '));

                                    });
                                }));
                            }
                        });

                        $('#image-name').text(d.image);
                        $('#image-version').text(d.version);
                        $('#image-branch').text(d.branch);
                        $('#parent-image').text(parent_name);
                        $('#parent-version').text(parent_version);

                        var complete = $('#complete')
                        var delta = $('#delta')
                        var parents = $('#parents')

                        var j;
                        for( j = 0; j < data.complete_whitelist.length; j++ ) {
                            var item = data.complete_whitelist[j];
                            $('#complete').append($("<tr>").html(convertVulnURLtoHTML(item)));
                        }
                        for( j = 0; j < data.parents_whitelist.length; j++ ) {
                            var item = data.parents_whitelist[j];
                            $('#parents').append($("<tr>").html(convertVulnURLtoHTML(item)));
                        }
                        for( j = 0; j < data.delta_whitelist.length; j++ ) {
                            var item = data.delta_whitelist[j];
                            $('#delta').append($("<tr>").html(convertVulnURLtoHTML(item)));
                        }

                    });
                }
            });
            $('#btn-list').append($("<a class='btn btn-secondary'></a>" ).html(but))

         //   $('#btn-list').append($("<li>").html(but))
        }
//        btnList.append('</ul>');

    });


    var $loading = $('#loadingDiv').hide();
    $(document)
        .ajaxStart(function() {
            $loading.show();
        })
        .ajaxStop(function() {
            $loading.hide();
        });

});

function clearAll(){
    $('#image-name').empty();
    $('#image-version').empty();
    $('#image-branch').empty();
    $('#parent-image').empty();
    $('#parent-version').empty();
    $('#delta').empty();
    $('#complete').empty();
    $('#parents').empty();
    $('#runs').empty();
    $('#runs').empty();
    $('#delta-list').empty();
    $('#delta-count').empty();
    clearJenkinsDetailsTable();
}

function clearJenkinsDetailsTable(){
    $('#total').empty()
    $('#oscap').empty()
    $('#oval').empty()
    $('#twistlock').empty()
    $('#anchore').empty()
}

function convertVulnURLtoHTML(vuln) {
    var cve_base = "https://nvd.nist.gov/vuln/detail/"
    var cce_base = "http://www.scaprepo.com/view.jsp?id="
    var rhba_base = "https://access.redhat.com/errata/"

    url = "http://www.google.com";
    if( vuln.includes("CVE") ){
        url = cve_base + vuln;
    }
    else if( vuln.includes("CCE") ) {
        url = cce_base + vuln;
    }
    else if( vuln.includes("RHBA") ) {
        url = rhba_base + vuln;
    }
    return( "<a href=" + url + " target=&quot;_blank&quot;>" + vuln + "</a>" );
}

function getTotalDelta(set1, set2) {
//    console.log("SET DUMP LOL", set1, set2)
    var _difference = new Set(set1);
    for ( var elem of set2 ) {
        _difference.delete(elem);
    }
    return _difference;
}
