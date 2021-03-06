var validators = {
    integer: function(a) {
        return null != a.match(/^-?[0-9]+$/)
    },
    uinteger: function(a) {
        return validators.integer(a) && 0 <= a
    },
    "float": function(a) {
        return ! isNaN(parseFloat(a))
    },
    ufloat: function(a) {
        return validators["float"](a) && 0 <= a
    },
    ipaddr: function(a) {
        return validators.ip4addr(a) || validators.ip6addr(a)
    },
    neg_ipaddr: function(a) {
        return validators.ip4addr(a.replace(/^\s*!/, "")) || validators.ip6addr(a.replace(/^\s*!/, ""))
    },
    ip4addr: function(a) {
        return a.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)(\/(\d+))?$/) ? 0 < RegExp.$1 && 223 >= RegExp.$1 && 0 <= RegExp.$2 && 255 >= RegExp.$2 && 0 <= RegExp.$3 && 255 >= RegExp.$3 && 0 < RegExp.$4 && 255 > RegExp.$4 && (!RegExp.$5 || 0 <= RegExp.$6 && 32 >= RegExp.$6) : !1
    },
    netmask: function(a) {
        return a.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)(\/(\d+))?$/) ? 0 <= RegExp.$1 && 255 >= RegExp.$1 && 0 <= RegExp.$2 && 255 >= RegExp.$2 && 0 <= RegExp.$3 && 255 >= RegExp.$3 && 0 <= RegExp.$4 && 255 >= RegExp.$4 && (!RegExp.$5 || 0 <= RegExp.$6 && 32 >= RegExp.$6) : !1
    },
    neg_ip4addr: function(a) {
        return validators.ip4addr(a.replace(/^\s*!/, ""))
    },
    ip6addr: function(a) {
        if (a.match(/^([a-fA-F0-9:.]+)(\/(\d+))?$/) && (!RegExp.$2 || 0 <= RegExp.$3 && 128 >= RegExp.$3)) {
            a = RegExp.$1;
            if ("::" == a) return ! 0;
            if (0 < a.indexOf(".")) {
                var b = a.lastIndexOf(":");
                if (!b || !validators.ip4addr(a.substr(b + 1))) return ! 1;
                a = a.substr(0, b) + ":0:0"
            }
            if (0 <= a.indexOf("::")) {
                for (var b = 0,
                d = "0",
                c = 1; c < a.length - 1; c++)":" == a.charAt(c) && b++;
                if (7 < b) return ! 1;
                for (c = 0; c < 7 - b; c++) d += ":0";
                a.match(/^(.*?)::(.*?)$/) && (a = (RegExp.$1 ? RegExp.$1 + ":": "") + d + (RegExp.$2 ? ":" + RegExp.$2: ""))
            }
            return null != a.match(/^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$/)
        }
        return ! 1
    },
    port: function(a) {
        return validators.integer(a) && 0 < a && 65535 >= a
    },
    portrange: function(a) {
        if (a.match(/^(\d+)-(\d+)$/)) {
            var a = RegExp.$1,
            b = RegExp.$2;
            return validators.port(a) && validators.port(b) && parseInt(a) <= parseInt(b)
        }
        return validators.port(a)
    },
    macaddr: function(a) {
        return null != a.match(/^([a-fA-F0-9]{2}(:|-)){5}[a-fA-F0-9]{2}$/)
    },
    host: function(a) {
        return validators.hostname(a) || validators.ipaddr(a)
    },
    hostname: function(a) {
        return 253 >= a.length ? null != a.match(/^[a-zA-Z0-9][a-zA-Z0-9\-.]*[a-zA-Z0-9]$/) : !1
    },
    wpakey: function(a) {
        return 64 == a.length ? null != a.match(/^[a-fA-F0-9]{64}$/) : 8 <= a.length && 63 >= a.length
    },
    wepkey: function(a) {
        "s:" == a.substr(0, 2) && (a = a.substr(2));
        return 10 == a.length || 26 == a.length ? null != a.match(/^[a-fA-F0-9]{10,26}$/) : 5 == a.length || 13 == a.length
    },
    uciname: function(a) {
        return null != a.match(/^[a-zA-Z0-9_]+$/)
    },
    neg_network_ip4addr: function(a) {
        a = a.replace(/^\s*!/, "");
        return validators.uciname(a) || validators.ip4addr(a)
    },
    range: function(a, b) {
        var d = parseInt(b[0]),
        c = parseInt(b[1]),
        e = parseInt(a);
        return ! isNaN(d) && !isNaN(c) && !isNaN(e) ? e >= d && e <= c: !1
    },
    min: function(a, b) {
        var d = parseInt(b[0]),
        c = parseInt(a);
        return ! isNaN(d) && !isNaN(c) ? c >= d: !1
    },
    max: function(a, b) {
        var d = parseInt(b[0]),
        c = parseInt(a);
        return ! isNaN(d) && !isNaN(c) ? c <= d: !1
    },
    neg: function(a, b) {
        return b[0] && "function" == typeof validators[b[0]] ? validators[b[0]](a.replace(/^\s*!\s*/, "")) : !1
    },
	ssid: function(a){
		var myreg = new RegExp("[`~!@#$%^&*()=+|{}':;',\\[\\]<>/?~！￥……（）【】‘；：”“'。，、？§№☆★○●◎◇◆℃‰€°¤〓↓↑←→※▲△■＃＆＠＼︿♂♀]");
		return myreg.test(a)
	},
	limit: function(a) {
        return validators.integer(a) && 0 <= a && 38400 >= a //30MB
    },
	equal: function( x, y ) {
		if ( x == y ) {
			return true;
		}
		if ( ! ( x instanceof Object ) || ! ( y instanceof Object ) ) { 
			return false;
		}
		if ( x.constructor !== y.constructor ) { 
			return false;
		}
		for ( var p in x ) { 
			if ( x.hasOwnProperty( p ) ) { 
				if ( ! y.hasOwnProperty( p ) ) { 
					return false; 
				}
				if ( x[ p ] === y[ p ] ) { 
					continue; 
				}
				if ( typeof( x[ p ] ) !== "object" ) { 
					return false; 
				}
				if ( ! Object.equals( x[ p ], y[ p ] ) ) { 
					return false; 
				} 
			} 
		}	 
		for ( p in y ) { 
			if ( y.hasOwnProperty( p ) && ! x.hasOwnProperty( p ) ) { 
				return false; 
			}
		} 
		return true;
	},
	url: function(a) {
        return null != a.match(/(((^https?:(?:\/\/)?)(?:[-;:&=\+\$,\w]+@)?[A-Za-z0-9.-]+|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:\/[\+~%\/.\w-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?)$/g)
    },	
	extdomain: function(a) {
        return null != a.match(/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)\.+[a-zA-Z]{2,6}$/g)
    },	
	domain: function(a) {
        return null != a.match(/^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$/g)
    },
	email: function(a) {
        return null != a.match(/^([a-zA-Z0-9]+[_|\_|\.]?)*[a-zA-Z0-9]+@([a-zA-Z0-9]+[_|\_|\.]?)*[a-zA-Z0-9]+\.[a-zA-Z]{2,3}$/)
    },
};
