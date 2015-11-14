/// <reference path="jquery-1.8.0.min.js" />
//.loadingpage_bg { background: none repeat scroll 0 0 #fff; display: block; height: 100%; left: 0; /*:rgba(0,0,0,0.5);*/ opacity: 0.1; filter: alpha(opacity=50); position: absolute; top: 0; width: 100%; z-index: 110; }
//#loadingpage { display: block; font-weight: bold; font-size: 12px; color: #595959; height: 28px; left: 50%; line-height: 27px; margin-left: -74px; margin-top: -14px; padding: 10px 10px 10px 50px; position: absolute; text-align: left; top: 50%; width: 148px; z-index: 111; background: url(img/loading.gif) no-repeat scroll 12px center #ffffff; border: 2px solid #86a5ad; }


var commonperson = {};
commonperson.base = {};
commonperson.base.loadingpic = {
    operation: {
        timetest: null,
        loadingcount: 0,
        loadingimgurl: "img/loading.gif",
        loadingimgheight: 24,
        loadingimgwidth: 24
    },

    fullscreenshow: function (msg) {
        if (msg === undefined) {
            msg = "loading data, please wait...";
        }

        if ($("#div_loadingimg").length == 0) {
            $("body").append("<div id='div_loadingimg'></div>");
        }
        if (this.operation.loadingcount < 1) {
            this.operation.timetest = settimeout(function () {
                $("#div_loadingimg").append("<div id='loadingpage_bg' class='loadingpage_bg1'></div><div id='loadingpage'>" + msg + "</div>");
                $("#loadingpage_bg").height($(top.window.document).height()).width($(top.window.document).width());
            }, 100);
        }
        this.operation.loadingcount += 1;
    },

    fullscreenhide: function () {
        this.operation.loadingcount -= 1;
        if (this.operation.loadingcount <= 0) {
            cleartimeout(this.operation.timetest);
            $("#div_loadingimg").empty();
            $("#div_loadingimg").remove();
            this.operation.loadingcount = 0;
        }
    },

    partshow: function (parentcontainerid, url, msg) {
        $("#" + parentcontainerid.replace("#", "").replace(".", "") + "_loadingimg").remove();
        var imgurl = '';
        if (url) {
            imgurl = url;
        } else {
            imgurl = this.operation.loadingimgurl;
        }

        if (msg === undefined) {
            msg = "loading...";
        }

        var htmltext = ' <div id="' + parentcontainerid + '_loadingimg" class="loadingpage_bg"><div style="display: block; font-weight: bold; font-size: 12px; color: #595959; height: 28px; left: 50%; line-height: 27px; padding: 10px 10px 10px 50px; width: 240px; z-index: 111; background: url(img/loading.gif) no-repeat scroll 12px center #ffffff; border: 2px solid #86a5ad;">' + msg + '</div></div>'
        $("#" + parentcontainerid).append(htmltext);
    },

    parthide: function (parentcontainerid) {
        $("#" + parentcontainerid.replace("#", "").replace(".", "") + "_loadingimg").remove();
    },

    partonlyimgshow: function (parentcontainerid, url) {
        $("#" + parentcontainerid.replace("#", "").replace(".", "") + "_zhezhao").remove();
        var parentcontainer = $("#" + parentcontainerid);
        var imgtop = parentcontainer.height() / 2 - this.operation.loadingimgheight / 2;
        var imgleft = parentcontainer.width() / 2 - this.operation.loadingimgwidth / 2;

        var imgurl = '';
        if (url) {
            imgurl = url;
        } else {
            imgurl = this.operation.loadingimgurl;
        }

        var htmltext = '<div id="' + parentcontainerid.replace("#", "").replace(".", "") + '_zhezhao" class="loadingpage_bg" style="margin:10px;display:block;position: absolute; width:' + parentcontainer.width() + 'px; border: 1px solid #d6e9f1; z-index:1002;"><img style="position: absolute; top:' + imgtop + 'px; left:' + imgleft + 'px; border: 1px solid #d6e9f1;" src="' + imgurl + '"/> </div>'
        $("body").append(htmltext);

        var zhezhao = $("#" + parentcontainerid.replace("#", "").replace(".", "") + "_zhezhao");
        zhezhao.css("top", parentcontainer.offset().top + "px");
        zhezhao.css("left", parentcontainer.offset().left + "px");
        zhezhao.css("width", parentcontainer.width() + "px");
    },

    partonlyimghide: function (parentcontainerid) {
        $("#" + parentcontainerid.replace("#", "").replace(".", "") + "_zhezhao").remove();
    }

}