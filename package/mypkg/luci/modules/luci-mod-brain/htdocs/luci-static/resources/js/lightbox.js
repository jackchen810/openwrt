/**
 * Created by lidandan on 2016/10/18.
 */
;(function($){
    var LightBox = function(msg,title){
        var self = this;
        //创建弹框
        this.popupMask = $('<div id="G-lightbox-mask">');
        this.popupWin = $('<div id="G-lightbox-popup">');
        this.bodyNode = $(document.body);
        this.renderDom(msg,title);

    };
    LightBox.prototype = {
        //渲染弹出dom，插入到body
        renderDom : function(msg,title){
            var strDom ='<div class="lightbox-pic-title">'+title+
                        '</div>'+
                        '<div class="lightbox-pic-view">'+
                            //'<img class="lightbox-image" src="<%=resource%>/images//loading2.gif" alt=""/>'+
                         '</div>'+
                        '<div class="lightbox-pic-caption">'+
                            '<div class="lightbox-caption-area">'+
                                '<p class="lightbox-pic-desc">'+ msg +'</p>'+
                            '</div>'+
                            '<span class="lightbox-close-btn"></span>'+
                        '</div>';
            //插入到popupWin
            this.popupWin.html(strDom);
            this.bodyNode.append(this.popupMask,this.popupWin);
        },
        showMaskAndPopup : function(captionText) {
            var self = this;
            self.captionText.html(captionText);
        }
    };
    window["LightBox"] = LightBox;

})(jQuery)