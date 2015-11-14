window.single_tab = "  ";
window.imgcollapsed = "../static/collapsed.gif";
window.imgexpanded = "../static/expanded.gif";
window.quotekeys = true;
function $id(id) {
    return document.getelementbyid(id);
}
function isarray(obj) {
    return  obj &&
        typeof obj === 'object' &&
        typeof obj.length === 'number' && !(obj.propertyisenumerable('length'));
}

function process(json, eid) {
    settab();
    window.iscollapsible = true;//$id("collapsibleview").checked;
    var html = "";
    try {
        if (json == "") json = "\"\"";
        var obj = eval("[" + json + "]");
        html = processobject(obj[0], 0, false, false, false);
        $id(eid).innerhtml = "<pre class='codecontainer'>" + html + "</pre>";
        collapseallclicked(eid);
    } catch (e) {
        alert("json format error:\n" + e.message);
        $id(eid).innerhtml = "";
    }
}
window._dateobj = new date();
window._regexpobj = new regexp();
function processobject(obj, indent, addcomma, isarray, ispropertycontent) {
    var html = "";
    var comma = (addcomma) ? "<span class='comma'>,</span> " : "";
    var type = typeof obj;
    var clpshtml = "";
    if (isarray(obj)) {
        if (obj.length == 0) {
            html += getrow(indent, "<span class='arraybrace'>[ ]</span>" + comma, ispropertycontent);
        } else {
            clpshtml = window.iscollapsible ? "<span><img src=\"" + window.imgexpanded + "\" onclick=\"expimgclicked(this)\" /></span><span class='collapsible'>" : "";
            html += getrow(indent, "<span class='arraybrace'>[</span>" + clpshtml, ispropertycontent);
            for (var i = 0; i < obj.length; i++) {
                html += processobject(obj[i], indent + 1, i < (obj.length - 1), true, false);
            }
            clpshtml = window.iscollapsible ? "</span>" : "";
            html += getrow(indent, clpshtml + "<span class='arraybrace'>]</span>" + comma);
        }
    } else if (type == 'object') {
        if (obj == null) {
            html += formatliteral("null", "", comma, indent, isarray, "null");
        } else if (obj.constructor == window._dateobj.constructor) {
            html += formatliteral("new date(" + obj.gettime() + ") /*" + obj.tolocalestring() + "*/", "", comma, indent, isarray, "date");
        } else if (obj.constructor == window._regexpobj.constructor) {
            html += formatliteral("new regexp(" + obj + ")", "", comma, indent, isarray, "regexp");
        } else {
            var numprops = 0;
            for (var prop in obj) numprops++;
            if (numprops == 0) {
                html += getrow(indent, "<span class='objectbrace'>{ }</span>" + comma, ispropertycontent);
            } else {
                clpshtml = window.iscollapsible ? "<span><img src=\"" + window.imgexpanded + "\" onclick=\"expimgclicked(this)\" /></span><span class='collapsible'>" : "";
                html += getrow(indent, "<span class='objectbrace'>{</span>" + clpshtml, ispropertycontent);

                var j = 0;

                for (var prop in obj) {

                    var quote = window.quotekeys ? "\"" : "";

                    html += getrow(indent + 1, "<span class='propertyname'>" + quote + prop + quote + "</span>: " + processobject(obj[prop], indent + 1, ++j < numprops, false, true));

                }

                clpshtml = window.iscollapsible ? "</span>" : "";

                html += getrow(indent, clpshtml + "<span class='objectbrace'>}</span>" + comma);

            }

        }

    } else if (type == 'number') {

        html += formatliteral(obj, "", comma, indent, isarray, "number");

    } else if (type == 'boolean') {

        html += formatliteral(obj, "", comma, indent, isarray, "boolean");

    } else if (type == 'function') {

        if (obj.constructor == window._regexpobj.constructor) {

            html += formatliteral("new regexp(" + obj + ")", "", comma, indent, isarray, "regexp");

        } else {

            obj = formatfunction(indent, obj);

            html += formatliteral(obj, "", comma, indent, isarray, "function");

        }

    } else if (type == 'undefined') {

        html += formatliteral("undefined", "", comma, indent, isarray, "null");

    } else {

        html += formatliteral(obj.tostring().split("\\").join("\\\\").split('"').join('\\"'), "\"", comma, indent, isarray, "string");

    }

    return html;

}

function formatliteral(literal, quote, comma, indent, isarray, style) {

    if (typeof literal == 'string')

        literal = literal.split("<").join("&lt;").split(">").join("&gt;");

    var str = "<span class='" + style + "'>" + quote + literal + quote + comma + "</span>";

    if (isarray) str = getrow(indent, str);

    return str;

}

function formatfunction(indent, obj) {

    var tabs = "";

    for (var i = 0; i < indent; i++) tabs += window.tab;

    var funcstrarray = obj.tostring().split("\n");

    var str = "";

    for (var i = 0; i < funcstrarray.length; i++) {

        str += ((i == 0) ? "" : tabs) + funcstrarray[i] + "\n";

    }

    return str;

}

function getrow(indent, data, ispropertycontent) {

    var tabs = "";

    for (var i = 0; i < indent && !ispropertycontent; i++) tabs += window.tab;

    if (data != null && data.length > 0 && data.charat(data.length - 1) != "\n")

        data = data + "\n";

    return tabs + data;

}

function collapsibleviewclicked() {

    $id("collapsibleviewdetail").style.visibility = $id("collapsibleview").checked ? "visible" : "hidden";

    process();

}


function quotekeysclicked() {

    window.quotekeys = $id("quotekeys").checked;

    process();

}


function collapseallclicked(eid) {

    ensureispopulated(eid);

    traversechildren($id(eid), function (element) {

        if (element.classname == 'collapsible') {

            makecontentvisible(element, false);

        }

    }, 0);

}

function expandallclicked(eid) {

    ensureispopulated(eid);

    traversechildren($id(eid), function (element) {

        if (element.classname == 'collapsible') {

            makecontentvisible(element, true);

        }

    }, 0);

}

function makecontentvisible(element, visible) {

    var img = element.previoussibling.firstchild;

    if (!!img.tagname && img.tagname.tolowercase() == "img") {

        element.style.display = visible ? 'inline' : 'none';

        element.previoussibling.firstchild.src = visible ? window.imgexpanded : window.imgcollapsed;

    }

}

function traversechildren(element, func, depth) {

    for (var i = 0; i < element.childnodes.length; i++) {

        traversechildren(element.childnodes[i], func, depth + 1);

    }

    func(element, depth);

}

function expimgclicked(img) {

    var container = img.parentnode.nextsibling;

    if (!container) return;

    var disp = "none";

    var src = window.imgcollapsed;

    if (container.style.display == "none") {

        disp = "inline";

        src = window.imgexpanded;

    }

    container.style.display = disp;

    img.src = src;

}

function collapselevel(level) {

    ensureispopulated();

    traversechildren($id("canvas"), function (element, depth) {

        if (element.classname == 'collapsible') {

            if (depth >= level) {

                makecontentvisible(element, false);

            } else {

                makecontentvisible(element, true);

            }

        }

    }, 0);

}

function tabsizechanged() {

    process();

}

function settab() {

//  var select = $id("tabsize");

    window.tab = multiplystring(2, window.single_tab);

}

function ensureispopulated(eid) {

    if (!$id(eid).innerhtml && !!$id("rawjson").value) process();

}

function multiplystring(num, str) {

    var sb = [];

    for (var i = 0; i < num; i++) {

        sb.push(str);

    }

    return sb.join("");

}

function selectallclicked() {


    if (!!document.selection && !!document.selection.empty) {

        document.selection.empty();

    } else if (window.getselection) {

        var sel = window.getselection();

        if (sel.removeallranges) {

            window.getselection().removeallranges();

        }

    }


    var range =

        (!!document.body && !!document.body.createtextrange)

            ? document.body.createtextrange()

            : document.createrange();


    if (!!range.selectnode)

        range.selectnode($id("canvas"));

    else if (range.movetoelementtext)

        range.movetoelementtext($id("canvas"));


    if (!!range.select)

        range.select($id("canvas"));

    else

        window.getselection().addrange(range);

}

function linktojson() {

    var val = $id("rawjson").value;

    val = escape(val.split('/n').join(' ').split('/r').join(' '));

    $id("invisiblelinkurl").value = val;

    $id("invisiblelink").submit();

}