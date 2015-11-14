_uacct = "ua-59572162-1"; //for google-analytics
urchintracker();
function onload() {
    var version = getsilverlightversion();
    if (version) {
        __utmsetvar(version);
    }
}
function getsilverlightversion() {

    var version = 'no silverlight';

    var container = null;

    try {

        var control = null;

        if (window.activexobject) {

            control = new activexobject('agcontrol.agcontrol');

        }

        else {

            if (navigator.plugins['silverlight plug-in']) {

                container = document.createelement('div');

                document.body.appendchild(container);

                container.innerhtml = '<embed type="application/x-silverlight" src="data:," />';

                control = container.childnodes[0];

            }

        }

        if (control) {

            if (control.isversionsupported('5.0')) {
                version = 'silverlight/5.0';
            }

            else if (control.isversionsupported('4.0')) {
                version = 'silverlight/4.0';
            }

            else if (control.isversionsupported('3.0')) {
                version = 'silverlight/3.0';
            }

            else if (control.isversionsupported('2.0')) {
                version = 'silverlight/2.0';
            }
            else if (control.isversionsupported('1.0')) {
                version = 'silverlight/1.0';
            }
        }
    }
    catch (e) {
    }
    if (container) {
        document.body.removechild(container);
    }
    return version;
}
onload();